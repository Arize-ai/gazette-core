package protocol

import (
	"net/url"
	"strings"
)

// FragmentStore defines a storage backend base path for Journal Fragments.
// It is a URL, where the scheme defines the storage backend service. As
// FragmentStores "root" remote storage locations of fragments, their path
// component must end in a trailing slash.
//
// Currently supported schemes are "gs" for Google Cloud Storage, "s3" for
// Amazon S3, "azure" for Azure Cloud Storage, and "file" for a local file-system / NFS mount. Eg:
//
//   - s3://bucket-name/a/sub-path/?profile=a-shared-credentials-profile
//   - gs://bucket-name/a/sub-path/?
//   - file:///a/local/volume/mount
//
// FragmentStore implementations may support additional configuration which
// can be declared via URL query arguments. The meaning of these query
// arguments and values are specific to the store in question; consult
// FileStoreConfig, S3StoreConfig, and GSStoreConfig of the fragment
// package for details of available configuration.
type FragmentStore string

// Validate returns an error if the FragmentStore is not well-formed.
func (fs FragmentStore) Validate() error {
	var _, err = fs.parse()
	return err
}

// URL returns the FragmentStore as a URL. The FragmentStore must Validate, or URL panics.
func (fs FragmentStore) URL() *url.URL {
	if url, err := fs.parse(); err == nil {
		return url
	} else {
		panic(err.Error())
	}
}

func (fs FragmentStore) parse() (*url.URL, error) {
	var url, err = parseFragmentStoreURL(string(fs))
	if err != nil {
		return nil, &ValidationError{Err: err}
	} else if !url.IsAbs() {
		return nil, NewValidationError("not absolute (%s)", fs)
	}

	switch url.Scheme {
	case "s3", "gs", "azure":
		if url.Host == "" {
			return nil, NewValidationError("missing bucket (%s)", fs)
		}
	case "azure-ad":
		var splitPath = strings.Split(url.Path[1:], "/")
		if url.Host == "" {
			return nil, NewValidationError("missing tenant ID (%s)", fs)
		} else if splitPath[0] == "" {
			return nil, NewValidationError("missing storage account (%s)", fs)
		} else if splitPath[1] == "" {
			return nil, NewValidationError("missing storage container (%s)", fs)
		}
	case "file":
		if url.Host != "" {
			return nil, NewValidationError("file scheme cannot have host (%s)", fs)
		}
	default:
		return nil, NewValidationError("invalid scheme (%s)", url.Scheme)
	}

	if path := url.Path; len(path) == 0 || path[len(path)-1] != '/' {
		return nil, NewValidationError("path component doesn't end in '/' (%s)", url.Path)
	}
	return url, nil
}

// parseFragmentStoreURL parses a fragment store URL. It transparently handles
// S3 Access Point and Multi-Region Access Point (MRAP) bucket ARNs used as the
// "bucket". An ARN such as
//
//	arn:aws:s3::123456789012:accesspoint/my-alias.mrap
//
// embeds colons (which net/url misreads as a host:port) and a slash (which it
// misreads as the start of the path), so a bare url.Parse rejects it with
// "invalid port" errors. We instead split the bucket ARN from the object key
// prefix at the slash following the access-point / MRAP name, and assemble the
// url.URL directly. The remainder is the object key prefix, exactly as a
// conventional s3://bucket/prefix/ URL.
func parseFragmentStoreURL(raw string) (*url.URL, error) {
	const s3ARNPrefix = "s3://arn:"
	const apMarker = ":accesspoint/"

	if !strings.HasPrefix(raw, s3ARNPrefix) {
		return url.Parse(raw)
	}

	// Separate the query string, if present.
	var rest = raw[len("s3://"):]
	var rawQuery string
	if i := strings.IndexByte(rest, '?'); i != -1 {
		rest, rawQuery = rest[:i], rest[i+1:]
	}

	// The bucket ARN ends with the access-point / MRAP name that immediately
	// follows ":accesspoint/". The next '/' (or end of string) begins the
	// object key prefix.
	var ap = strings.Index(rest, apMarker)
	if ap == -1 {
		return url.Parse(raw) // Not an access-point ARN; let net/url report.
	}

	var nameStart = ap + len(apMarker)
	var bucket, path string
	if slash := strings.IndexByte(rest[nameStart:], '/'); slash == -1 {
		bucket, path = rest, ""
	} else {
		var boundary = nameStart + slash
		bucket, path = rest[:boundary], rest[boundary:]
	}

	return &url.URL{
		Scheme:   "s3",
		Host:     bucket,
		Path:     path,
		RawQuery: rawQuery,
	}, nil
}

func fragmentStoresEq(a, b []FragmentStore) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
