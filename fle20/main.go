// Show how the prototype FLE 2.0 API is used for a common use case.

// Assumes the key vault and data are in separate MongoDB clusters.
// Performs an insert and query on the "ssn" field with automatic encryption.
//
// To build this example, libmongocrypt must be installed. Build with:
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

// The following are configurable by environment variables.
var (
	MONGODB_URI_KEYVAULT string
	MONGODB_URI_DATA     string
	LOCAL_KEK            string
	EFC_FILE             string
)

// setup creates the "health.blood" collection with encrypted fields.
// Documents are expected to be of this form:
// {
// 	name: <unencrypted string>
// 	ssn: <encrypted with equality index>
// 	blood_type: <encrypted with no index>
// }
func setup() {
	ctx := context.Background()

	keyVaultClient, err := mongo.Connect(ctx, options.Client().ApplyURI(MONGODB_URI_KEYVAULT))
	if err != nil {
		log.Fatalf("error in Connect to keyVaultClient: %v", err)
	}
	defer keyVaultClient.Disconnect(ctx)

	dataClient, err := mongo.Connect(ctx, options.Client().ApplyURI(MONGODB_URI_DATA))
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

	localKEK, err := base64.StdEncoding.DecodeString(LOCAL_KEK)
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
	fmt.Println("Created 'health.blood' collection.")
	efcJSON, err := bson.MarshalExtJSONIndent(efc, true /* canonical */, false /* escapeHTML */, "", " ")
	if err != nil {
		log.Fatalf("error in MarshalExtJSONIndent: %v", err)
	}
	err = os.WriteFile(EFC_FILE, efcJSON, 0644)
	if err != nil {
		log.Fatalf("error writing to file %v: %v", EFC_FILE, err)
	}
	fmt.Printf("The following has been saved to %v:\n", EFC_FILE)
	fmt.Println(string(efcJSON))
}

type Record struct {
	Name       string
	Ssn        string
	Blood_type string
}

// getEncryptedClient returns a new mongo.Client configured with automatic encryption.
func getEncryptedClient(ctx context.Context) *mongo.Client {
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

	localKEK, err := base64.StdEncoding.DecodeString(LOCAL_KEK)
	if err != nil {
		log.Fatalf("LOCAL_KEK is not valid base64: %v", err)
	}

	kmsProviders := map[string]map[string]interface{}{
		"local": {
			"key": localKEK,
		},
	}

	// Create client with automatic encryption.
	aeo := options.AutoEncryption().
		SetKmsProviders(kmsProviders).
		SetKeyVaultNamespace("keyvault.datakeys").
		SetEncryptedFieldConfigMap(map[string]options.EncryptedFieldConfig{
			"health.blood": efc,
		}).
		SetKeyVaultClientOptions(options.Client().ApplyURI(MONGODB_URI_KEYVAULT))

	encryptedClient, err := mongo.Connect(ctx, options.Client().ApplyURI(MONGODB_URI_DATA).SetAutoEncryptionOptions(aeo))
	if err != nil {
		log.Fatalf("error in Connect to encryptedClient: %v", err)
	}
	return encryptedClient
}

// insert adds a record to "health.blood".
func insert(name string, ssn string, blood_type string) {
	ctx := context.Background()

	encryptedClient := getEncryptedClient(ctx)
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
func findOne(ssn string) {
	ctx := context.Background()
	encryptedClient := getEncryptedClient(ctx)
	defer encryptedClient.Disconnect(ctx)

	coll := encryptedClient.Database("health").Collection("blood")
	res := coll.FindOne(ctx, bson.D{{"ssn", ssn}})
	if res.Err() != nil {
		log.Fatalf("error in FindOne: %v", res.Err())
	}
	var record Record
	err := res.Decode(&record)
	if err != nil {
		log.Fatalf("error in Decode: %v", err)
	}
	fmt.Printf("Got record: %v\n", record)
}

func printHelpAndExit() {
	fmt.Printf("Usage: fle2poc [setup|insert|find] <args>")
	fmt.Println("To create the 'health.blood' collection:")
	fmt.Println(" fle2poc setup")
	fmt.Println("To insert a record to the 'health.blood' collection:")
	fmt.Println(" fle2poc insert <name> <ssn> <blood_type>")
	fmt.Println("To find a record to the 'health.blood' collection by ssn:")
	fmt.Println(" fle2poc findOne <ssn>")
	fmt.Println("These environment variables can be configured:")
	fmt.Println(" MONGODB_URI_KEYVAULT for the URI of the MongoDB cluster containing encrypted data keys.")
	fmt.Println(" MONGODB_URI_DATA for the MongoDB cluster containing encrypted data keys.")
	fmt.Println(" LOCAL_KEK for the 96 byte Key Encryption Key")
	fmt.Println(" EFC_FILE for the path to the file containing the Encrypted Field Config")
	os.Exit(1)
}

func main() {
	if len(os.Args) == 1 {
		printHelpAndExit()
	}

	// Load environment variables.
	var found bool

	MONGODB_URI_KEYVAULT, found = os.LookupEnv("MONGODB_URI_KEYVAULT")
	if !found {
		MONGODB_URI_KEYVAULT = "mongodb://localhost:27017"
	}

	MONGODB_URI_DATA, found = os.LookupEnv("MONGODB_URI_DATA")
	if !found {
		MONGODB_URI_DATA = "mongodb://localhost:27017"
	}

	LOCAL_KEK, found = os.LookupEnv("LOCAL_KEK")
	if !found {
		log.Fatal("LOCAL_KEK environment variable must be set to a 96 byte base64 string. Try:\n" +
			"export LOCAL_KEK=$(openssl rand -base64 96)")
	}

	EFC_FILE, found = os.LookupEnv("EFC_FILE")
	if !found {
		log.Fatalf("EFC_FILE environment variable must be set to the file path containing the Encrypted Field Config JSON\n" +
			"Try: fle2poc setup")
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
