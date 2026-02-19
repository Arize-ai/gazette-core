package azure

import (
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/sas"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/service"
	"github.com/Azure/azure-storage-blob-go/azblob"
	log "github.com/sirupsen/logrus"
	"go.gazette.dev/core/broker/stores"
)

// accountStore implements the Store interface for Azure Blob Storage
// using Shared Key authentication (azure:// scheme)
type accountStore struct {
	storeBase
	sasKey *service.SharedKeyCredential
}

// NewAccount creates a new Azure Store from the provided URL (azure://container/prefix).
// Authentication is chosen in order:
//   - If AZURE_ACCOUNT_NAME and AZURE_ACCOUNT_KEY are set: Shared Key (existing behavior, backwards compatible).
//   - Else if AZURE_ACCOUNT_NAME, AZURE_TENANT_ID, and both AZURE_CLIENT_ID and AZURE_CLIENT_SECRET are set: client secret.
//   - Else if AZURE_ACCOUNT_NAME and AZURE_TENANT_ID are set: DefaultAzureCredential (workload identity, managed identity, Azure CLI).
//
// So existing customers keep using azure:// with account key; migrating to managed identity only requires setting AZURE_TENANT_ID and removing the key (and optionally AZURE_CLIENT_ID for workload identity).
func NewAccount(ep *url.URL) (stores.Store, error) {
	var args StoreQueryArgs

	if err := parseStoreArgs(ep, &args); err != nil {
		return nil, err
	}

	var container = ep.Host
	var prefix = ep.Path[1:]

	var storageAccount = os.Getenv("AZURE_ACCOUNT_NAME")
	var accountKey = os.Getenv("AZURE_ACCOUNT_KEY")

	var blobDomain = os.Getenv("AZURE_BLOB_DOMAIN")
	if blobDomain == "" {
		blobDomain = "blob.core.windows.net"
	}

	// Shared Key: backwards-compatible path for existing azure:// users.
	if storageAccount != "" && accountKey != "" {
		credentials, err := azblob.NewSharedKeyCredential(storageAccount, accountKey)
		if err != nil {
			return nil, err
		}

		var pipeline = azblob.NewPipeline(credentials, azblob.PipelineOptions{})

		sasKey, err := service.NewSharedKeyCredential(storageAccount, accountKey)
		if err != nil {
			return nil, err
		}

		var store = &accountStore{
			storeBase: storeBase{
				storageAccount: storageAccount,
				blobDomain:     blobDomain,
				container:      container,
				prefix:         prefix,
				args:           args,
				pipeline:       pipeline,
			},
			sasKey: sasKey,
		}

		log.WithFields(log.Fields{
			"storageAccount": storageAccount,
			"blobDomain":     blobDomain,
			"container":      container,
			"prefix":         prefix,
		}).Info("constructed new Azure Shared Key storage client")

		return store, nil
	}

	// AD auth (client secret or workload/managed identity): requires tenant and storage account from env.
	var tenantID = os.Getenv("AZURE_TENANT_ID")
	if storageAccount == "" || tenantID == "" {
		return nil, fmt.Errorf("azure:// requires either AZURE_ACCOUNT_NAME+AZURE_ACCOUNT_KEY (shared key) or AZURE_ACCOUNT_NAME+AZURE_TENANT_ID (AD / workload identity)")
	}

	var credentials azcore.TokenCredential
	var err error
	var clientID = os.Getenv("AZURE_CLIENT_ID")
	var clientSecret = os.Getenv("AZURE_CLIENT_SECRET")
	var authMethod string
	if clientID != "" && clientSecret != "" {
		credentials, err = azidentity.NewClientSecretCredential(
			tenantID,
			clientID,
			clientSecret,
			&azidentity.ClientSecretCredentialOptions{
				DisableInstanceDiscovery: true,
			},
		)
		if err != nil {
			return nil, err
		}
		authMethod = "client secret"
	} else {
		credentials, err = azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
			TenantID:                 tenantID,
			DisableInstanceDiscovery: true,
		})
		if err != nil {
			return nil, err
		}
		authMethod = "workload identity / default chain"
	}

	return newADStoreFromCredential(tenantID, storageAccount, container, prefix, blobDomain, args, credentials, authMethod)
}

// SignGet returns a signed URL for GET operations using Shared Key signing
func (a *accountStore) SignGet(path string, d time.Duration) (string, error) {
	var blob = a.args.RewritePath(a.prefix, path)

	sasQueryParams, err := sas.BlobSignatureValues{
		Protocol:      sas.ProtocolHTTPS,
		ExpiryTime:    time.Now().UTC().Add(d),
		ContainerName: a.container,
		BlobName:      blob,
		Permissions:   to.Ptr(sas.BlobPermissions{Read: true}).String(),
	}.SignWithSharedKey(a.sasKey)

	if err != nil {
		return "", err
	}

	log.WithFields(log.Fields{
		"storageAccount": a.storageAccount,
		"blobDomain":     a.blobDomain,
		"container":      a.container,
		"blob":           blob,
		"expires":        sasQueryParams.ExpiryTime(),
	}).Debug("Signed get request with shared key")

	return fmt.Sprintf("%s/%s?%s", a.containerURL(), blob, sasQueryParams.Encode()), nil
}
