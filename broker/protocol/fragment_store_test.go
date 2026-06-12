package protocol

import (
	"net/url"

	gc "gopkg.in/check.v1"
)

type FragmentStoreSuite struct{}

func (s *FragmentStoreSuite) TestValidation(c *gc.C) {
	var cases = []struct {
		fs     FragmentStore
		expect string
	}{
		{"s3://my-bucket/?query", ""},         // Success.
		{"s3://my-bucket/subpath/?query", ""}, // Success (non-empty prefix).
		{"file:///mnt/path/", ``},             // Success.
		{"file:///mnt/path/?query", ``},       // Success.

		// S3 Multi-Region Access Point (MRAP) bucket ARN, with prefix and query.
		{"s3://arn:aws:s3::123456789012:accesspoint/my-alias.mrap/arize/fragments/?endpoint=https%3A%2F%2Fmy-alias.mrap.accesspoint.s3-global.amazonaws.com&sse=aws%3Akms", ""},
		// S3 Access Point bucket ARN at the bucket root.
		{"s3://arn:aws:s3:us-east-1:123456789012:accesspoint/my-ap/", ""},

		// MRAP ARN without a trailing slash is still rejected like any other store.
		{"s3://arn:aws:s3::123456789012:accesspoint/my-alias.mrap", `path component doesn't end in '/' \(\)`},

		{"s3://my-bucket", `path component doesn't end in '/' \(\)`},
		{"s3://my-bucket/subpath?query", `path component doesn't end in '/' \(/subpath\)`},
		{":garbage: :garbage:", "parse .* missing protocol scheme"},
		{"foobar://baz/", `invalid scheme \(foobar\)`},
		{"/baz/bing/", `not absolute \(/baz/bing/\)`},
		{"gs:///baz/bing/", `missing bucket \(gs:///baz/bing/\)`},
		{"file://host/mnt/path/", `file scheme cannot have host \(file://host/mnt/path/\)`},
		{"file:///mnt/path", `path component doesn't end in '/' \(/mnt/path\)`},
	}
	for _, tc := range cases {
		if tc.expect == "" {
			c.Check(tc.fs.Validate(), gc.IsNil)
		} else {
			c.Check(tc.fs.Validate(), gc.ErrorMatches, tc.expect)
		}
	}
}

func (s *FragmentStoreSuite) TestURLConversion(c *gc.C) {
	var fs FragmentStore = "s3://bucket/sub/path/?query"
	c.Check(fs.URL(), gc.DeepEquals, &url.URL{
		Scheme:   "s3",
		Host:     "bucket",
		Path:     "/sub/path/",
		RawQuery: "query",
	})

	fs = "/baz/bing/"
	c.Check(func() { fs.URL() }, gc.PanicMatches, `not absolute \(/baz/bing/\)`)

	// An MRAP bucket ARN splits into the full ARN host and object key prefix,
	// preserving the query string (including its percent-encoded values).
	fs = "s3://arn:aws:s3::123456789012:accesspoint/my-alias.mrap/arize/fragments/?sse=aws%3Akms"
	c.Check(fs.URL(), gc.DeepEquals, &url.URL{
		Scheme:   "s3",
		Host:     "arn:aws:s3::123456789012:accesspoint/my-alias.mrap",
		Path:     "/arize/fragments/",
		RawQuery: "sse=aws%3Akms",
	})
}

var _ = gc.Suite(&FragmentStoreSuite{})
