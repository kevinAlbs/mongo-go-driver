// Copyright (C) MongoDB, Inc. 2021-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

//go:build cse
// +build cse

package integration

import (
	"context"
	"fmt"
	"testing"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/internal/testutil/assert"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/integration/mtest"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// TestFLE20CreateCollection tests creating a collection.
func TestFLE20CreateCollection(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().MinServerVersion("5.0").Enterprise(true).CreateClient(false))
	defer mt.Close()

	kmsProvidersMap := map[string]map[string]interface{}{
		"local": {"key": localMasterKey},
	}

	mt.Run("Is it possible for CreateCollection to accept a ClientEncryption option?", func(mt *mtest.T) {
		// Create key vault client.
		kvClientOptions := options.Client().ApplyURI(mtest.ClusterURI())
		kvClient, err := mongo.Connect(context.TODO(), kvClientOptions)
		defer kvClient.Disconnect(context.TODO())
		assert.Nil(mt, err, "error in kvClient Connect: %v", err)

		// Create a ClientEncryption object.
		ceOpts := options.ClientEncryption().SetKeyVaultNamespace("keyvault.datakeys").SetKmsProviders(kmsProvidersMap)
		ce, err := mongo.NewClientEncryption(kvClient, ceOpts)
		defer ce.Close(context.TODO())
		assert.Nil(mt, err, "error in NewClientEncryption: %v", err)

		// Create data Client.
		clientOptions := options.Client().ApplyURI(mtest.ClusterURI())
		client, err := mongo.Connect(context.TODO(), clientOptions)
		defer client.Disconnect(context.TODO())
		assert.Nil(mt, err, "error in Connect: %v", err)

		db := client.Database("db")
		db.Collection("encrypted").Drop(context.TODO())
		err = db.CreateCollection(context.TODO(), "encrypted", options.CreateCollection())
		assert.Nil(mt, err, "error in CreateCollection: %v", err)
		/* Answer: No
		 * Attempting to add an import from 'options' to 'mongo' package creates an import cycle.
		 * package go.mongodb.org/mongo-driver/mongo/integration (test)
					imports go.mongodb.org/mongo-driver/internal/testutil
					imports go.mongodb.org/mongo-driver/mongo/options
					imports go.mongodb.org/mongo-driver/mongo
					imports go.mongodb.org/mongo-driver/mongo/options: import cycle not allowed
			FAIL    go.mongodb.org/mongo-driver/mongo/integration [setup failed]
		*/
	})

	mt.Run("Can ClientEncryption generate the encryptedFields options?", func(mt *mtest.T) {
		// Create a KeyVault client.
		kvClientOptions := options.Client().ApplyURI(mtest.ClusterURI())
		kvClient, err := mongo.Connect(context.TODO(), kvClientOptions)
		defer kvClient.Disconnect(context.TODO())
		assert.Nil(mt, err, "error in kvClient Connect: %v", err)

		// Create a ClientEncryption object.
		ceOpts := options.ClientEncryption().SetKeyVaultNamespace("keyvault.datakeys").SetKmsProviders(kmsProvidersMap)
		ce, err := mongo.NewClientEncryption(kvClient, ceOpts)
		defer ce.Close(context.TODO())
		assert.Nil(mt, err, "error in NewClientEncryption: %v", err)

		eco := options.EncryptedCollectionOptions{
			ESCCollection:  "foo_esc",
			ECCCollection:  "foo_ecc",
			ECOCCollection: "foo_ecoc",
			Fields: []options.EncryptedFieldOptions{
				{
					Path:     "ssn",
					BSONType: "string",
					Queries: []options.EncryptedQueryOptions{
						{QueryType: "equality"},
					},
				},
			},
		}

		fmt.Printf("Before: %v\n", eco)
		err = ce.AddKeysToEncryptedCollectionOptions(context.TODO(), &eco, "local", nil)
		fmt.Printf("After: %v\n", eco)
	})

	mt.Run("Q: Can ClientEncryption.CreateCollection wrap Database.CreateCollection? A: Yes", func(mt *mtest.T) {
		// Create a KeyVault client.
		kvClientOptions := options.Client().ApplyURI(mtest.ClusterURI())
		kvClient, err := mongo.Connect(context.TODO(), kvClientOptions)
		defer kvClient.Disconnect(context.TODO())
		assert.Nil(mt, err, "error in kvClient Connect: %v", err)

		// Create a ClientEncryption object.
		ceOpts := options.ClientEncryption().SetKeyVaultNamespace("keyvault.datakeys").SetKmsProviders(kmsProvidersMap)
		ce, err := mongo.NewClientEncryption(kvClient, ceOpts)
		defer ce.Close(context.TODO())
		assert.Nil(mt, err, "error in NewClientEncryption: %v", err)

		// Create a data client.
		client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(mtest.ClusterURI()))
		assert.Nil(t, err, "error in data client Connect: %v", err)
		defer client.Disconnect(context.TODO())

		eco := options.EncryptedCollectionOptions{
			ESCCollection:  "foo_esc",
			ECCCollection:  "foo_ecc",
			ECOCCollection: "foo_ecoc",
			Fields: []options.EncryptedFieldOptions{
				{
					Path:     "ssn",
					BSONType: "string",
					Queries: []options.EncryptedQueryOptions{
						{QueryType: "equality"},
					},
				},
			},
		}

		cco := options.CreateCollection().SetEncryptedCollectionOptions(&eco)
		db := client.Database("db")
		db.Collection("coll").Drop(context.TODO())
		err = ce.CreateCollection(context.TODO(), db, "coll", "local", nil, cco)
		fmt.Printf("error in CreateCollection: %v\n", eco)
	})
}

func TestFLE2ExplicitEncryption(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().MinServerVersion("5.0").CreateClient(false))
	defer mt.Close()

	kmsProvidersMap := map[string]map[string]interface{}{
		"local": {"key": localMasterKey},
	}

	mt.Run("Explicit encrypt IndexType=None", func(mt *mtest.T) {
		// Create key vault client.
		kvClientOptions := options.Client().ApplyURI(mtest.ClusterURI())
		kvClient, err := mongo.Connect(context.TODO(), kvClientOptions)
		defer kvClient.Disconnect(context.TODO())
		assert.Nil(mt, err, "error in kvClient Connect: %v", err)

		// Create a ClientEncryption object.
		ceOpts := options.ClientEncryption().SetKeyVaultNamespace("keyvault.datakeys").SetKmsProviders(kmsProvidersMap)
		ce, err := mongo.NewClientEncryption(kvClient, ceOpts)
		defer ce.Close(context.TODO())
		assert.Nil(mt, err, "error in NewClientEncryption: %v", err)

		// Create a data key.
		keyid, err := ce.CreateDataKey(context.TODO(), "local")
		assert.Nil(mt, err, "error in CreateDataKey: %v", err)

		// Create EncryptOptions.
		eOpts := options.Encrypt().SetKeyID(keyid).SetEncryptIndexType(options.EncryptIndexNone)
		// TODO: once libmongocrypt supports IndexType, remove SetAlgorithm.
		eOpts.SetAlgorithm("AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic")
		bsonType, bytes, err := bson.MarshalValue("foo")
		assert.Nil(mt, err, "error in MarshalValue: %v", err)
		toEncrypt := bson.RawValue{Type: bsonType, Value: bytes}
		ciphertext, err := ce.Encrypt(context.TODO(), toEncrypt, eOpts)
		assert.Nil(mt, err, "error in Encrypt: %v", err)
		assert.Equal(mt, ciphertext.Subtype, byte(6), "expected ciphertext binary subtype 0x06, got: %v", ciphertext.Subtype)
		// TODO: once libmongocrypt supports IndexType, expect the first byte to be 0x04.
		assert.Equal(mt, ciphertext.Data[0], byte(1), "expected ciphertext payload type 0x01, got: %v", ciphertext.Data[0])
		mt.Logf("'ciphertext' is encoded as: %x\n", ciphertext.Data)
	})
}

func TestFLE2Compact(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().MinServerVersion("5.0").CreateClient(false))

	mt.Run("Compact", func(mt *mtest.T) {
		kvClient := mt.Client
		kmsProviders := map[string]map[string]interface{}{
			"local": {
				"key": localMasterKey,
			},
		}
		ceOpts := options.ClientEncryption().SetKeyVaultNamespace("keyvault.datakeys").SetKmsProviders(kmsProviders)
		ce, err := mongo.NewClientEncryption(kvClient, ceOpts)
		assert.Nil(mt, err, "error in NewClientEncryption: %v", err)
		defer ce.Close(context.TODO())

		keyid, err := ce.CreateDataKey(context.TODO(), "local")
		assert.Nil(mt, err, "error in CreateDataKey: %v", err)

		dataClient, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(mtest.ClusterURI()))
		assert.Nil(mt, err, "error in Connect: %v", err)

		coll := dataClient.Database("foo").Collection("bar")
		efc := options.EncryptedFieldConfig{
			Fields: []options.EncryptedField{{
				KeyID:    &keyid,
				Path:     "ssn",
				BSONType: "string",
				Queries: []options.QueryTypeConfig{{
					QueryType: "Equality",
				}},
			}},
		}
		res := ce.Compact(context.TODO(), coll, &efc)
		assert.Nil(mt, res.Err(), "error in Compact: %v", res)
	})
}
