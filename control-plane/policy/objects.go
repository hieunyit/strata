package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// ErrObjectNotFound: Get of a key the store does not have.
var ErrObjectNotFound = errors.New("policy: no such object")

// IsObjectNotFound reports whether err is a Get of a missing key.
func IsObjectNotFound(err error) bool { return errors.Is(err, ErrObjectNotFound) }

// Objects is where bundles are kept.
type Objects interface {
	Put(ctx context.Context, key string, data []byte, sha256hex string) error
	Get(ctx context.Context, key string) ([]byte, error)
}

// S3 stores objects in an S3-compatible bucket (MinIO in the lab).
type S3 struct {
	client *minio.Client
	bucket string
}

// S3Config of the object store.
type S3Config struct {
	Endpoint  string // host:port
	Bucket    string
	AccessKey string
	SecretKey string
	Secure    bool // HTTPS
}

// NewS3 connects and checks that the bucket exists.
func NewS3(ctx context.Context, cfg S3Config) (*S3, error) {
	c, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.Secure,
	})
	if err != nil {
		return nil, fmt.Errorf("policy: object store: %w", err)
	}
	ok, err := c.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("policy: object store: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("policy: bucket %s does not exist", cfg.Bucket)
	}
	return &S3{client: c, bucket: cfg.Bucket}, nil
}

// Put uploads data, with its SHA-256 as metadata and checksum.
func (s *S3) Put(ctx context.Context, key string, data []byte, sha256hex string) error {
	_, err := s.client.PutObject(ctx, s.bucket, key, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{
		ContentType:    "application/vnd.strata.bundle",
		UserMetadata:   map[string]string{"Sha256": sha256hex},
		SendContentMd5: true,
	})
	if err != nil {
		return fmt.Errorf("policy: upload %s: %w", key, err)
	}
	return nil
}

// Get downloads an object.
func (s *S3) Get(ctx context.Context, key string) ([]byte, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer obj.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(obj); err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return nil, fmt.Errorf("policy: download %s: %w", key, ErrObjectNotFound)
		}
		return nil, fmt.Errorf("policy: download %s: %w", key, err)
	}
	return buf.Bytes(), nil
}

// Open reads an object from offset on (FetchBundle resumes there).
func (s *S3) Open(ctx context.Context, key string, offset int64) (io.ReadCloser, error) {
	opts := minio.GetObjectOptions{}
	if offset > 0 {
		if err := opts.SetRange(offset, 0); err != nil {
			return nil, err
		}
	}
	obj, err := s.client.GetObject(ctx, s.bucket, key, opts)
	if err != nil {
		return nil, fmt.Errorf("policy: open %s: %w", key, err)
	}
	return obj, nil
}

// ObjectInfo is one entry of List.
type ObjectInfo struct {
	Key  string
	Size int64
}

// List returns the objects whose key starts with prefix, in key order.
func (s *S3) List(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	var out []ObjectInfo
	for o := range s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if o.Err != nil {
			return nil, fmt.Errorf("policy: list %s: %w", prefix, o.Err)
		}
		out = append(out, ObjectInfo{Key: o.Key, Size: o.Size})
	}
	return out, nil
}
