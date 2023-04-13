package operation

import (
	"runtime"
	"testing"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/internal/assert"
	"go.mongodb.org/mongo-driver/internal/require"
	"go.mongodb.org/mongo-driver/version"
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


func clearEnv(t *testing.T) {
	t.Setenv(envVarAWSExecutionEnv, "")
	t.Setenv(envVarAWSLambdaRuntimeAPI, "")
	t.Setenv(envVarFunctionsWorkerRuntime, "")
	t.Setenv(envVarKService, "")
	t.Setenv(envVarFunctionName, "")
	t.Setenv(envVarVercel, "")
	t.Setenv(envVarAWSRegion, "")
	t.Setenv(envVarAWSLambdaFunctionMemorySize, "")
	t.Setenv(envVarFunctionMemoryMB, "")
	t.Setenv(envVarFunctionTimeoutSec, "")
	t.Setenv(envVarFunctionRegion, "")
	t.Setenv(envVarVercelURL, "")
	t.Setenv(envVarVercelRegion, "")
}

func TestEncodeClientMetadata(t *testing.T) {
	// Clear environment variables that influence handshake.
	clearEnv(t)

	// Set environment variables to add `env` field to handshake.
	t.Setenv(envVarAWSLambdaRuntimeAPI, "lambda")
	t.Setenv(envVarAWSLambdaFunctionMemorySize, "123")
	t.Setenv(envVarAWSRegion, "region")

	// Test that nothing is omitted.
	{
		got, err := encodeClientMetadata("foo", 512)
		assert.Nil(t, err, "error in encodeClientMetadata: %v", err)

		expectD := bson.D{
			{"application", bson.D{
				{"name", "foo"},
			}},
			{"driver", bson.D{
				{"name", driverName},
				{"version", version.Driver},
			}},
			{"os", bson.D{
				{"type", runtime.GOOS},
				{"architecture", runtime.GOARCH},
			}},
			{"platform", runtime.Version()},
			{"env", bson.D{
				{"name", "aws.lambda"},
				{"memory_mb", 123},
				{"region", "region"},
			}},
		}
		expect, err := bson.Marshal(expectD)
		assert.Nil(t, err, "error in Marshal: %v", err)
		assert.Equal(t, expect, got, "expected: %s, but got %s", bson.Raw(expect), bson.Raw(got))
	}

	// Test that fields from `env`` are omitted first.
	{
		// Reduce max size to 225.
		got, err := encodeClientMetadata("foo", 225)
		assert.Nil(t, err, "error in encodeClientMetadata: %v", err)

		expectD := bson.D{
			{"application", bson.D{
				{"name", "foo"},
			}},
			{"driver", bson.D{
				{"name", driverName},
				{"version", version.Driver},
			}},
			{"os", bson.D{
				{"type", runtime.GOOS},
				{"architecture", runtime.GOARCH},
			}},
			{"platform", runtime.Version()},
			{"env", bson.D{
				{"name", "aws.lambda"},
			}},
		}
		expect, err := bson.Marshal(expectD)
		assert.Nil(t, err, "error in Marshal: %v", err)
		assert.Equal(t, expect, got, "expected: %s, but got %s", bson.Raw(expect), bson.Raw(got))
	}

	// Test that entire env document is omitted next.
	{
		// TODO.
	}

	// Test that fields from os are omitted next.
	{
		// TODO.
	}

	// Test that platform is truncated next.
	{
		// TODO.
	}

	// Test that empty slice is returned last.
	{
		// TODO.
	}
}
