package integration

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"testing"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/event"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"context"
	"io/ioutil"
)

// Test with: go test ./mongo/integration -tags cse -v -run TestSpec1768
// TODO: This is mega-jank.
//
const DEBUG = false

// readJSONFile1768 has the 1768 suffix to avoid symbol clash.
func readJSONFile1768(filename string) []byte {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	contents, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}

	return contents
}

func toJson1768(v interface{}) string {
	bytes, err := bson.MarshalExtJSON(v, true, false)
	if err != nil {
		log.Fatal(err)
	}
	return string(bytes)
}

type DeadlockTest struct {
	clientTest           *mongo.Client
	clientMetadataOpts   *options.ClientOptions
	clientMetadataEvents []bson.Raw
	clientKeyVaultOpts   *options.ClientOptions
	clientKeyVaultEvents []bson.Raw
	clientEncryption     *mongo.ClientEncryption
	ciphertext           primitive.Binary
	mutex                sync.Mutex
}

func getKMSProviders() map[string]map[string]interface{} {
	const localBase64 = "Mng0NCt4ZHVUYUJCa1kxNkVyNUR1QURhZ2h2UzR2d2RrZzh0cFBwM3R6NmdWMDFBMUN3YkQ5aXRRMkhGRGdQV09wOGVNYUMxT2k3NjZKelhaQmRCZGJkTXVyZG9uSjFk"
	raw, err := ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(localBase64)))
	if err != nil {
		log.Fatal(err)
	}

	kmsProviders := make(map[string]map[string]interface{})
	kmsProviders["local"] = make(map[string]interface{})
	kmsProviders["local"]["key"] = primitive.Binary{0, raw}
	return kmsProviders
}

func makeCaptureMonitor(name string, dest *[]bson.Raw, mutex *sync.Mutex) *event.CommandMonitor {
	return &event.CommandMonitor{func(ctx context.Context, event *event.CommandStartedEvent) {
		fmt.Printf("[%v] command started (%v, %v)\n", name, event.CommandName, event.DatabaseName)
		if DEBUG {
			fmt.Println(toJson1768(event.Command))
		}
		tmp := make(bson.Raw, len(event.Command))
		copy(tmp, event.Command)
		mutex.Lock()
		defer mutex.Unlock()
		*dest = append(*dest, tmp)
	}, nil, nil}
}

const uri = "mongodb://localhost:27017/?readConcernLevel=majority&w=majority"

func doTestSetup() *DeadlockTest {
	d := DeadlockTest{}
	ctx := context.Background()
	var err error

	clientTestOpts := options.Client().ApplyURI(uri).SetMaxPoolSize(1)
	if d.clientTest, err = mongo.Connect(ctx, clientTestOpts); err != nil {
		log.Fatal(err)
	}

	d.clientMetadataOpts = options.Client().ApplyURI(uri).SetMaxPoolSize(1)
	d.clientMetadataOpts.SetMonitor(makeCaptureMonitor("clientMetadata", &d.clientMetadataEvents, &d.mutex))

	// Go driver takes client options, not a client, to configure the key vault client.
	d.clientKeyVaultOpts = options.Client().ApplyURI(uri).SetMaxPoolSize(1)
	d.clientKeyVaultOpts.SetMonitor(makeCaptureMonitor("clientKeyVault", &d.clientKeyVaultEvents, &d.mutex))

	keyvaultColl := d.clientTest.Database("keyvault").Collection("datakeys")
	dataColl := d.clientTest.Database("db").Collection("coll")
	if err := dataColl.Drop(ctx); err != nil {
		log.Fatal(err)
	}

	if err := keyvaultColl.Drop(ctx); err != nil {
		log.Fatal(err)
	}

	var keyDoc bson.M
	keyDocJSON := readJSONFile1768("./spec1768/external-key.json")
	if err := bson.UnmarshalExtJSON(keyDocJSON, true, &keyDoc); err != nil {
		log.Fatal(err)
	}

	if _, err := keyvaultColl.InsertOne(ctx, keyDoc); err != nil {
		log.Fatal(err)
	}

	var schema bson.M
	schemaJSON := readJSONFile1768("./spec1768/external-schema.json")
	if err := bson.UnmarshalExtJSON(schemaJSON, true, &schema); err != nil {
		log.Fatal(err)
	}

	createOpts := options.CreateCollection().SetValidator(bson.M{"$jsonSchema": schema})
	if err := d.clientTest.Database("db").CreateCollection(ctx, "coll", createOpts); err != nil {
		log.Fatal(err)
	}

	kmsProviders := getKMSProviders()
	json, _ := bson.MarshalExtJSON(&kmsProviders, true, false)
	fmt.Println(string(json))
	ceOpts := options.ClientEncryption().SetKmsProviders(getKMSProviders()).SetKeyVaultNamespace("keyvault.datakeys")
	if d.clientEncryption, err = mongo.NewClientEncryption(d.clientTest, ceOpts); err != nil {
		log.Fatal(err)
	}

	var in bson.RawValue // TODO: there is probably a better way to create a bson.RawValue from a Go native type.
	if bytes, err := bson.Marshal(bson.M{"v": "string0"}); err != nil {
		log.Fatal(err)
	} else {
		asRaw := bson.Raw(bytes)
		in, err = asRaw.LookupErr("v")
		if err != nil {
			log.Fatal(err)
		}
	}

	d.ciphertext, err = d.clientEncryption.Encrypt(ctx, in, options.Encrypt().SetAlgorithm("AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic").SetKeyAltName("local"))
	if err != nil {
		log.Fatal(err)
	}

	return &d
}

func TestSpec1768(t *testing.T) {
	testcases := []struct {
		description                           string
		bypassAutoEncryptionSet               bool
		keyVaultClientSet                     bool
		metadataClientSet                     bool
		clientEncryptedCommandStartedExpected int
		clientKeyVaultCommandStartedExpected  int
		clientMetadataCommandStartedExpected  int
	}{
		{"case 1", false, false, false, 4, 0, 0},
		{"case 2", false, false, true, 3, 0, 1},
		{"case 3", false, true, false, 3, 1, 0},
		{"case 4", false, true, true, 2, 1, 1},
		{"case 5", true, false, false, 3, 0, 0},
		{"case 6", true, false, true, 3, 0, 0},
		{"case 7", true, true, false, 2, 1, 0},
		{"case 8", true, true, true, 2, 1, 0},
	}

	for _, tc := range testcases {
		t.Run(tc.description, func(t *testing.T) {
			var clientEncryptedEvents []bson.Raw

			d := doTestSetup()
			ctx := context.Background()
			aeOpts := options.AutoEncryption()
			aeOpts.SetKeyVaultNamespace("keyvault.datakeys")
			aeOpts.SetKmsProviders(getKMSProviders())
			if tc.keyVaultClientSet {
				aeOpts.SetKeyVaultClientOptions(d.clientKeyVaultOpts)
			}

			if tc.metadataClientSet {
				aeOpts.SetMetadataClientOptions(d.clientMetadataOpts)
			}

			aeOpts.SetBypassAutoEncryption(tc.bypassAutoEncryptionSet)

			ceOpts := options.Client().ApplyURI(uri)
			ceOpts.SetMonitor(makeCaptureMonitor("clientEncrypted", &clientEncryptedEvents, &d.mutex))
			ceOpts.SetMaxPoolSize(1)
			ceOpts.SetAutoEncryptionOptions(aeOpts)

			clientEncrypted, err := mongo.Connect(ctx, ceOpts)
			if err != nil {
				log.Fatal(err)
			}

			coll := clientEncrypted.Database("db").Collection("coll")
			if !tc.bypassAutoEncryptionSet {
				_, err = coll.InsertOne(ctx, bson.M{"_id": 0, "encrypted": "string0"})
			} else {
				_, err = coll.InsertOne(ctx, bson.M{"_id": 0, "encrypted": d.ciphertext})
			}
			if err != nil {
				log.Fatal(err)
			}

			res := coll.FindOne(ctx, bson.M{"_id": 0})
			if res.Err() != nil {
				log.Fatal(res.Err())
			}

			// TODO: what is the right way to compare BSON.
			if raw, err := res.DecodeBytes(); err != nil {
				log.Fatal(res.Err())
			} else {
				expected, _ := bson.Marshal(bson.D{{"_id", 0}, {"encrypted", "string0"}})
				if bytes.Compare(expected, raw) != 0 {
					log.Fatal("not equal")
				}
			}

			// TODO: actually compare the command started event commands, not just the lengths.
			if len(clientEncryptedEvents) != tc.clientEncryptedCommandStartedExpected {
				log.Fatalf("expected %v events in clientEncryptedEvents, got %v", tc.clientEncryptedCommandStartedExpected, len(clientEncryptedEvents))
			}

			if len(d.clientKeyVaultEvents) != tc.clientKeyVaultCommandStartedExpected {
				log.Fatalf("expected %v events in clientKeyVaultEvents, got %v", tc.clientKeyVaultCommandStartedExpected, len(d.clientKeyVaultEvents))
			}

			if len(d.clientMetadataEvents) != tc.clientMetadataCommandStartedExpected {
				log.Fatalf("expected %v events in clientMetadataEvents, got %v", tc.clientMetadataCommandStartedExpected, len(d.clientMetadataEvents))
			}

			var wg sync.WaitGroup
			for i := 1; i <= 10; i++ {
				wg.Add(1)
				go func(i int) {
					coll := clientEncrypted.Database("db").Collection("coll")
					if !tc.bypassAutoEncryptionSet {
						_, err = coll.InsertOne(ctx, bson.M{"_id": i, "encrypted": "string0"})
					} else {
						_, err = coll.InsertOne(ctx, bson.M{"_id": i, "encrypted": d.ciphertext})
					}
					if err != nil {
						log.Fatal(err)
					}

					res := coll.FindOne(ctx, bson.M{"_id": i})
					if res.Err() != nil {
						log.Fatal(res.Err())
					}
					// TODO: what is the right way to compare BSON.
					if raw, err := res.DecodeBytes(); err != nil {
						log.Fatal(res.Err())
					} else {
						expected, _ := bson.Marshal(bson.D{{"_id", i}, {"encrypted", "string0"}})
						if bytes.Compare(expected, raw) != 0 {
							log.Fatal("not equal")
						}
					}
					wg.Done()
				}(i)
				wg.Wait()
			}
		})
	}
}
