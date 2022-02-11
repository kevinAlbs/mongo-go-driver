// Show how the prototype FLE 2.0 API is used for a common use case.

// Assumes the key vault and data are in separate MongoDB clusters.
// Performs an insert and query on the "ssn" field with automatic encryption.
//
// To run this example, libmongocrypt must be installed. Build with:
// go build -tags cse -o fle2poc main.go

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// setup creates the "health.blood" collection with encrypted fields.
// The LOCAL_KEK environment variable must be set to a 96 byte base64 encoded string for the Key Encryption Key.
// The MONGODB_URI_KEYVAULT environment variable may be set. It defaults to mongodb://localhost:27017.
// The MONGODB_URI_DATA environment variable may be set. It defaults to mongodb://localhost:27017.
// Documents are expected to be of this form:
// {
// 	name: <unencrypted string>
// 	ssn: <encrypted with equality index>
// 	blood_type: <encrypted with no index>
// }
func setup() {
	ctx := context.Background()

	// keyVaultURI must refer to the MongoDB cluster containing encrypted data keys.
	keyVaultURI, found := os.LookupEnv("MONGODB_URI_KEYVAULT")
	if !found {
		keyVaultURI = "mongodb://localhost:27017"
	}

	keyVaultClient, err := mongo.Connect(ctx, options.Client().ApplyURI(keyVaultURI))
	if err != nil {
		log.Fatalf("error in Connect to keyVaultClient: %v", err)
	}
	defer keyVaultClient.Disconnect(ctx)

	// dataURI must refer to the MongoDB cluster containing encrypted data.
	dataURI, found := os.LookupEnv("MONGODB_URI_DATA")
	if !found {
		dataURI = "mongodb://localhost:27017"
	}

	dataClient, err := mongo.Connect(ctx, options.Client().ApplyURI(dataURI))
	if err != nil {
		log.Fatalf("error in Connect to dataClient: %v", err)
	}
	defer dataClient.Disconnect(ctx)

	// EncryptedFieldConfig describes the encrypted fields.
	// "ssn" can be queried with equality queries.
	// "blood" cannot be queried.
	efc := options.EncryptedFieldConfig{
		Fields: []options.EncryptedField{
			{
				Path:     "ssn",
				BSONType: "string",
				Queries: []options.QueryTypeConfig{
					{QueryType: "equality"},
				},
			},
			{
				Path:     "blood",
				BSONType: "string",
			},
		},
	}

	// localKEK is a 96 byte Key Encryption Key for the local KMS provider.
	localKEKBase64, found := os.LookupEnv("LOCAL_KEK")
	if !found {
		log.Fatal("LOCAL_KEK environment variable must be set to a 96 byte base64 string. Try:\n" +
			"export LOCAL_KEK=$(openssl rand -base64 96)")
	}
	localKEK, err := base64.StdEncoding.DecodeString(localKEKBase64)
	if err != nil {
		log.Fatalf("LOCAL_KEK is not valid base64: %v", err)
	}

	kmsProviders := map[string]map[string]interface{}{
		"local": {
			"key": localKEK,
		},
	}

	// Create a ClientEncryption struct to create an encrypted collection.
	ceOpts := options.ClientEncryption().
		SetKmsProviders(kmsProviders).
		SetKeyVaultNamespace("keyvault.datakeys")
	ce, err := mongo.NewClientEncryption(keyVaultClient, ceOpts)
	defer ce.Close(ctx)
	if err != nil {
		log.Fatalf("error in NewClientEncryption: %v", err)
	}

	// Create the encrypted collection "health.blood".
	// The EncryptedFieldConfig does not include Data Encryption Key KeyIDs.
	// CreateEncryptedCollection creates a separate Data Encryption Key for "ssn" and "blood".
	healthDB := dataClient.Database("health")
	// Drop the collection in case it exists from a previous run.
	err = ce.DropCollection(ctx, healthDB, "blood", &efc)
	if err != nil {
		log.Fatalf("error in DropEncryptedCollection: %v", err)
	}

	err = ce.CreateCollection(ctx, healthDB, "blood", "local", nil /* data key opts */, &efc)
	if err != nil {
		log.Fatalf("error in CreateEncryptedCollection: %v", err)
	}
	// TODO: this needs to overwrite the encrypted field config.
	// Print the canonical extended JSON of the resulting EncryptedFieldConfig.
	// This contains the KeyIDs created in CreateEncryptedCollection.
	fmt.Println("Created 'health.blood' collection. Please save the following:")
	efcJSON, err := bson.MarshalExtJSONIndent(efc, true /* canonical */, false /* escapeHTML */, "", " ")
	fmt.Println(string(efcJSON))
}

type Record struct {
	Name       string
	Ssn        string
	Blood_type string
}

// insert adds a record to "health.blood".
// The EFC_FILE environment variable must be set to a file path to the Encrypted Field Config created in setup.
// The LOCAL_KEK environment variable must be set to a 96 byte base64 encoded string for the Key Encryption Key.
// The MONGODB_URI_KEYVAULT environment variable may be set. It defaults to mongodb://localhost:27017.
// The MONGODB_URI_DATA environment variable may be set. It defaults to mongodb://localhost:27017.
func insert(name string, ssn string, blood_type string) {
	ctx := context.Background()
	// Get EncryptedFieldConfig from file.
	efcFile, found := os.LookupEnv("EFC_FILE")
	if !found {
		log.Fatalf("EFC_FILE environment variable must be set to the file path containing the Encrypted Field Config JSON\n" +
			"Try: fle2poc setup")
	}
	efcBytes, err := os.ReadFile(efcFile)
	if err != nil {
		log.Fatalf("error reading file %v: %v", efcFile, err)
	}
	var efc options.EncryptedFieldConfig
	err = bson.UnmarshalExtJSON(efcBytes, true /* canonical */, &efc)
	if err != nil {
		log.Fatalf("error loading Encrypted Field Config from %v: %v", efcFile, err)
	}

	// localKEK is a 96 byte Key Encryption Key for the local KMS provider.
	localKEKBase64, found := os.LookupEnv("LOCAL_KEK")
	if !found {
		log.Fatal("LOCAL_KEK environment variable must be set to a 96 byte base64 string. Try:\n" +
			"export LOCAL_KEK=$(openssl rand -base64 96)")
	}
	localKEK, err := base64.StdEncoding.DecodeString(localKEKBase64)
	if err != nil {
		log.Fatalf("LOCAL_KEK is not valid base64: %v", err)
	}

	kmsProviders := map[string]map[string]interface{}{
		"local": {
			"key": localKEK,
		},
	}

	// keyVaultURI must refer to the MongoDB cluster containing encrypted data keys.
	keyVaultURI, found := os.LookupEnv("MONGODB_URI_KEYVAULT")
	if !found {
		keyVaultURI = "mongodb://localhost:27017"
	}

	// Create client with automatic encryption.
	aeo := options.AutoEncryption().
		SetKmsProviders(kmsProviders).
		SetKeyVaultNamespace("keyvault.datakeys").
		SetEncryptedFieldConfigMap(map[string]options.EncryptedFieldConfig{
			"health.blood": efc,
		}).
		SetKeyVaultClientOptions(options.Client().ApplyURI(keyVaultURI))

	// dataURI must refer to the MongoDB cluster containing encrypted data.
	dataURI, found := os.LookupEnv("MONGODB_URI_DATA")
	if !found {
		dataURI = "mongodb://localhost:27017"
	}

	encryptedClient, err := mongo.Connect(ctx, options.Client().ApplyURI(dataURI).SetAutoEncryptionOptions(aeo))
	if err != nil {
		log.Fatalf("error in Connect to encryptedClient: %v", err)
	}
	defer encryptedClient.Disconnect(ctx)

	coll := encryptedClient.Database("health").Collection("blood")
	res, err := coll.InsertOne(ctx, Record{
		Name:       name,
		Ssn:        ssn,
		Blood_type: blood_type,
	})
	if err != nil {
		log.Fatalf("error in InsertOne: %v", err)
	}
	fmt.Printf("Inserted record with id: %v\n", res.InsertedID)
}

// findOne finds a record by querying the "ssn" field in the "health.blood" collection.
// The EFC_FILE environment variable must be set to a file path to the Encrypted Field Config created in setup.
// The LOCAL_KEK environment variable must be set to a 96 byte base64 encoded string for the Key Encryption Key.
// The MONGODB_URI_KEYVAULT environment variable may be set. It defaults to mongodb://localhost:27017.
// The MONGODB_URI_DATA environment variable may be set. It defaults to mongodb://localhost:27017.
func findOne(ssn string) {
	ctx := context.Background()
	// Get EncryptedFieldConfig from file.
	efcFile, found := os.LookupEnv("EFC_FILE")
	if !found {
		log.Fatalf("EFC_FILE environment variable must be set to the file path containing the Encrypted Field Config JSON\n" +
			"Try: fle2poc setup")
	}
	efcBytes, err := os.ReadFile(efcFile)
	if err != nil {
		log.Fatalf("error reading file %v: %v", efcFile, err)
	}
	var efc options.EncryptedFieldConfig
	err = bson.UnmarshalExtJSON(efcBytes, true /* canonical */, &efc)
	if err != nil {
		log.Fatalf("error loading Encrypted Field Config from %v: %v", efcFile, err)
	}

	// localKEK is a 96 byte Key Encryption Key for the local KMS provider.
	localKEKBase64, found := os.LookupEnv("LOCAL_KEK")
	if !found {
		log.Fatal("LOCAL_KEK environment variable must be set to a 96 byte base64 string. Try:\n" +
			"export LOCAL_KEK=$(openssl rand -base64 96)")
	}
	localKEK, err := base64.StdEncoding.DecodeString(localKEKBase64)
	if err != nil {
		log.Fatalf("LOCAL_KEK is not valid base64: %v", err)
	}

	kmsProviders := map[string]map[string]interface{}{
		"local": {
			"key": localKEK,
		},
	}

	// keyVaultURI must refer to the MongoDB cluster containing encrypted data keys.
	keyVaultURI, found := os.LookupEnv("MONGODB_URI_KEYVAULT")
	if !found {
		keyVaultURI = "mongodb://localhost:27017"
	}

	// Create client with automatic encryption.
	aeo := options.AutoEncryption().
		SetKmsProviders(kmsProviders).
		SetKeyVaultNamespace("keyvault.datakeys").
		SetEncryptedFieldConfigMap(map[string]options.EncryptedFieldConfig{
			"health.blood": efc,
		}).
		SetKeyVaultClientOptions(options.Client().ApplyURI(keyVaultURI))

	// dataURI must refer to the MongoDB cluster containing encrypted data.
	dataURI, found := os.LookupEnv("MONGODB_URI_DATA")
	if !found {
		dataURI = "mongodb://localhost:27017"
	}

	encryptedClient, err := mongo.Connect(ctx, options.Client().ApplyURI(dataURI).SetAutoEncryptionOptions(aeo))
	if err != nil {
		log.Fatalf("error in Connect to encryptedClient: %v", err)
	}
	defer encryptedClient.Disconnect(ctx)

	coll := encryptedClient.Database("health").Collection("blood")
	res := coll.FindOne(ctx, bson.D{{"ssn", ssn}})
	if res.Err() != nil {
		log.Fatalf("error in FindOne: %v", err)
	}
	var record Record
	err = res.Decode(&record)
	if err != nil {
		log.Fatalf("error in Decode: %v", err)
	}
	fmt.Printf("Got record: %v\n", record)
}

func printHelpAndExit() {
	fmt.Printf("Usage: fle2poc [setup|insert|find] <args>")
	fmt.Println("To create the 'health.blood' collection:")
	fmt.Println("fle2poc setup")
	fmt.Println("To insert a record to the 'health.blood' collection:")
	fmt.Println("fle2poc insert <name> <ssn> <blood_type>")
	fmt.Println("To find a record to the 'health.blood' collection by ssn:")
	fmt.Println("fle2poc findOne <ssn>")
	os.Exit(1)
}

func main() {
	if len(os.Args) == 1 {
		printHelpAndExit()
	}
	switch os.Args[1] {
	case "setup":
		setup()
		return
	case "insert":
		if len(os.Args) != 5 {
			printHelpAndExit()
		}
		insert(os.Args[2], os.Args[3], os.Args[4])
		return
	case "findOne":
		if len(os.Args) != 3 {
			printHelpAndExit()
		}
		findOne(os.Args[2])
		return
	default:
		printHelpAndExit()
	}
}
