package azure

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/sas"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/service"
	"github.com/Azure/azure-storage-blob-go/azblob"
	log "github.com/sirupsen/logrus"
	"go.gazette.dev/core/broker/stores"
)

// accountStore implements the Store interface for Azure Blob Storage
// using Shared Key authentication (azure:// scheme).
type accountStore struct {
	storeBase
	sasKey *service.SharedKeyCredential
}

// NewAccount creates an azure:// store from the provided URL.
// It will use managed identity if the account key is not set.
func NewAccount(ep *url.URL) (stores.Store, error) {
	var args StoreQueryArgs

	if err := parseStoreArgs(ep, &args); err != nil {
		return nil, err
	}

	var container = ep.Host
	var prefix = ep.Path[1:]

	var storageAccount = os.Getenv("AZURE_ACCOUNT_NAME")
	var accountKey = os.Getenv("AZURE_ACCOUNT_KEY")
	var tenantID = os.Getenv("AZURE_TENANT_ID")
	var clientID = os.Getenv("AZURE_CLIENT_ID")

	if storageAccount == "" {
		return nil, fmt.Errorf("AZURE_ACCOUNT_NAME must be set for azure:// URLs")
	}
	if accountKey == "" && (tenantID == "" || clientID == "") {
		return nil, fmt.Errorf("AZURE_ACCOUNT_KEY or both AZURE_CLIENT_ID and AZURE_TENANT_ID must be set for azure:// URLs")
	}
	if accountKey == "" {
		return newManagedIdentityStore(args, tenantID, clientID, storageAccount, container, prefix)
	}

	// arize change to support china cloud
	blobDomain := os.Getenv("AZURE_BLOB_DOMAIN")
	if blobDomain == "" {
		blobDomain = "blob.core.windows.net"
	}

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

func newManagedIdentityStore(args StoreQueryArgs, tenantID string, clientID string, storageAccount string, container string, prefix string) (stores.Store, error) {
	// arize change to support china cloud
	blobDomain := os.Getenv("AZURE_BLOB_DOMAIN")
	if blobDomain == "" {
		blobDomain = "blob.core.windows.net"
	}

	credentials, err := azidentity.NewManagedIdentityCredential(&azidentity.ManagedIdentityCredentialOptions{
		ID: azidentity.ClientID(clientID),
	})
	if err != nil {
		return nil, err
	}

	var refreshFn = func(credential azblob.TokenCredential) time.Duration {
		if token, err := credentials.GetToken(
			context.Background(),
			policy.TokenRequestOptions{
				TenantID: tenantID,
				Scopes:   []string{"https://storage.azure.com/.default"}},
		); err != nil {
			log.WithFields(log.Fields{
				"err":    err,
				"tenant": tenantID,
			}).Errorf("failed to refresh Azure credential (will retry)")

			return time.Minute
		} else {
			credential.SetToken(token.Token)
			return token.ExpiresOn.Sub(time.Now().Add(time.Minute))
		}
	}
	var accessKey = azblob.NewTokenCredential("", refreshFn)

	client, err := service.NewClient(
		azureStorageURL(storageAccount, blobDomain),
		credentials,
		&service.ClientOptions{},
	)
	if err != nil {
		return nil, err
	}

	var store = &adStore{
		storeBase: storeBase{
			storageAccount: storageAccount,
			blobDomain:     blobDomain,
			container:      container,
			prefix:         prefix,
			args:           args,
			pipeline:       azblob.NewPipeline(accessKey, azblob.PipelineOptions{}),
		},
		tenantID: tenantID,
		client:   client,
	}

	log.WithFields(log.Fields{
		"tenant":         tenantID,
		"clientID":       clientID,
		"storageAccount": storageAccount,
		"blobDomain":     blobDomain,
		"container":      container,
		"prefix":         prefix,
		"auth":           "managed identity",
	}).Info("constructed new Azure managed identity storage client")

	return store, nil
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
