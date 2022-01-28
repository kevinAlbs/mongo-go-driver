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
	"testing"

	"go.mongodb.org/mongo-driver/internal/testutil/assert"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/integration/mtest"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// TestFLE20CreateCollection tests creating a collection.
func TestFLE20CreateCollection(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().MinServerVersion("5.0").Enterprise(true).CreateClient(false))
	defer mt.Close()

	mt.Run("Is it possible for CreateCollection to accept a ClientEncryption option?", func(mt *mtest.T) {
		// Create key vault client.
		kvClientOptions := options.Client().ApplyURI(mtest.ClusterURI())
		kvClient, err := mongo.Connect(context.TODO(), kvClientOptions)
		defer kvClient.Disconnect(context.TODO())
		assert.Nil(mt, err, "error in kvClient Connect: %v", err)

		// Create a ClientEncryption object.
		ceOpts := options.ClientEncryption().SetKeyVaultNamespace("keyvault.datakeys")
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
}
