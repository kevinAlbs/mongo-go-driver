package operation

import (
	"testing"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/internal/assert"
	"go.mongodb.org/mongo-driver/internal/require"
	"go.mongodb.org/mongo-driver/x/bsonx/bsoncore"
)

const documentSize = 5         // 5 bytes to start and end a document
const embeddedDocumentSize = 7 // 7 bytes to append a document element
const stringElementSize = 7    // 7 bytes to append a string element
const int32ElementSize = 6     // 6 bytes to append an int32 element

func assertAppendClientMaxLen(t *testing.T, got bsoncore.Document, wantD bson.D, maxLen int) {
	t.Helper()

	tooLarge := len(got)-documentSize > maxLen
	require.False(t, tooLarge, "got document is too large: %v", got)

	var gotD bson.D
	err := bson.Unmarshal(got, &gotD)
	require.NoError(t, err, "error unmarshaling got document: %v", err)

	assert.Equal(t, wantD, gotD, "got %v, want %v", gotD, wantD)
}

func encodeWithCallback(t *testing.T, cb func(int, []byte) ([]byte, error)) bsoncore.Document {
	t.Helper()

	var err error
	idx, dst := bsoncore.AppendDocumentStart(nil)

	dst, err = cb(len(dst), dst)
	require.NoError(t, err, "error appending client metadata: %v", err)

	dst, err = bsoncore.AppendDocumentEnd(dst, idx)
	require.NoError(t, err, "error appending document end: %v", err)

	got, _, ok := bsoncore.ReadDocument(dst)
	require.True(t, ok, "error reading document: %v", got)

	return got
}

func TestParseFaasEnvName(t *testing.T) {
	for _, test := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "no env",
			want: "",
		},
		{
			name: "one aws",
			env: map[string]string{
				"AWS_EXECUTION_ENV": "hello",
			},
			want: "aws.lambda",
		},
		{
			name: "both aws options",
			env: map[string]string{
				"AWS_EXECUTION_ENV":      "hello",
				"AWS_LAMBDA_RUNTIME_API": "hello",
			},
			want: "aws.lambda",
		},
		{
			name: "multiple variables",
			env: map[string]string{
				"AWS_EXECUTION_ENV":        "hello",
				"FUNCTIONS_WORKER_RUNTIME": "hello",
			},
			want: "",
		},
	} {
		test := test

		t.Run(test.name, func(t *testing.T) {
			for k, v := range test.env {
				t.Setenv(k, v)
			}

			got := getFaasEnvName()
			if got != test.want {
				t.Errorf("parseFaasEnvName(%s) = %s, want %s",
					test.name, got, test.want)
			}
		})
	}
}

func BenchmarkClientMetadata(b *testing.B) {
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := encodeClientMetadata("foo", maxClientMetadataSize)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func FuzzEncodeClientMetadata(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte, appname string) {
		if len(b) > maxClientMetadataSize {
			return
		}

		_, err := encodeClientMetadata(appname, maxClientMetadataSize)
		if err != nil {
			t.Fatalf("error appending client: %v", err)
		}

		_, err = appendClientAppName(b, appname)
		if err != nil {
			t.Fatalf("error appending client app name: %v", err)
		}

		_, err = appendClientDriver(b)
		if err != nil {
			t.Fatalf("error appending client driver: %v", err)
		}

		_, err = appendClientEnv(b)
		if err != nil {
			t.Fatalf("error appending client env: %v", err)
		}

		_, err = appendClientOS(b)
		if err != nil {
			t.Fatalf("error appending client os: %v", err)
		}

		appendClientPlatform(b)
	})
}
