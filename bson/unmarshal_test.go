// Copyright (C) MongoDB, Inc. 2017-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package bson

import (
	"crypto/rand"
	"reflect"
	"testing"
	"unsafe"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/bsoncodec"
	"go.mongodb.org/mongo-driver/bson/bsonrw"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func TestUnmarshal(t *testing.T) {
	for _, tc := range unmarshalingTestCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.reg != nil {
				t.Skip() // test requires custom registry
			}
			got := reflect.New(tc.sType).Interface()
			err := Unmarshal(tc.data, got)
			noerr(t, err)
			if !cmp.Equal(got, tc.want) {
				t.Errorf("Did not unmarshal as expected. got %v; want %v", got, tc.want)
			}
		})
	}
}

func TestUnmarshalWithRegistry(t *testing.T) {
	for _, tc := range unmarshalingTestCases {
		t.Run(tc.name, func(t *testing.T) {
			var reg *bsoncodec.Registry
			if tc.reg != nil {
				reg = tc.reg
			} else {
				reg = DefaultRegistry
			}
			got := reflect.New(tc.sType).Interface()
			err := UnmarshalWithRegistry(reg, tc.data, got)
			noerr(t, err)
			if !cmp.Equal(got, tc.want) {
				t.Errorf("Did not unmarshal as expected. got %v; want %v", got, tc.want)
			}
		})
	}
}

func TestUnmarshalWithContext(t *testing.T) {
	for _, tc := range unmarshalingTestCases {
		t.Run(tc.name, func(t *testing.T) {
			var reg *bsoncodec.Registry
			if tc.reg != nil {
				reg = tc.reg
			} else {
				reg = DefaultRegistry
			}
			dc := bsoncodec.DecodeContext{Registry: reg}
			got := reflect.New(tc.sType).Interface()
			err := UnmarshalWithContext(dc, tc.data, got)
			noerr(t, err)
			if !cmp.Equal(got, tc.want) {
				t.Errorf("Did not unmarshal as expected. got %v; want %v", got, tc.want)
			}
		})
	}
}

func TestUnmarshalExtJSONWithRegistry(t *testing.T) {
	t.Run("UnmarshalExtJSONWithContext", func(t *testing.T) {
		type teststruct struct{ Foo int }
		var got teststruct
		data := []byte("{\"foo\":1}")
		err := UnmarshalExtJSONWithRegistry(DefaultRegistry, data, true, &got)
		noerr(t, err)
		want := teststruct{1}
		if !cmp.Equal(got, want) {
			t.Errorf("Did not unmarshal as expected. got %v; want %v", got, want)
		}
	})

	t.Run("UnmarshalExtJSONInvalidInput", func(t *testing.T) {
		data := []byte("invalid")
		err := UnmarshalExtJSONWithRegistry(DefaultRegistry, data, true, &M{})
		if err != bsonrw.ErrInvalidJSON {
			t.Fatalf("wanted ErrInvalidJSON, got %v", err)
		}
	})
}

func TestUnmarshalExtJSONWithContext(t *testing.T) {
	t.Run("UnmarshalExtJSONWithContext", func(t *testing.T) {
		type teststruct struct{ Foo int }
		var got teststruct
		data := []byte("{\"foo\":1}")
		dc := bsoncodec.DecodeContext{Registry: DefaultRegistry}
		err := UnmarshalExtJSONWithContext(dc, data, true, &got)
		noerr(t, err)
		want := teststruct{1}
		if !cmp.Equal(got, want) {
			t.Errorf("Did not unmarshal as expected. got %v; want %v", got, want)
		}
	})
}

// GODRIVER-2311
// Assert that unmarshaled values containing byte slices do not reference the same underlying byte
// array as the BSON input data byte slice.
func TestUnmarshalByteSlicesUseDistinctArrays(t *testing.T) {
	type fooBytes struct {
		Foo []byte
	}

	type myBytes []byte
	type fooMyBytes struct {
		Foo myBytes
	}

	type fooBinary struct {
		Foo primitive.Binary
	}

	type fooObjectID struct {
		Foo primitive.ObjectID
	}

	type fooDBPointer struct {
		Foo primitive.DBPointer
	}

	testCases := []struct {
		description string
		data        []byte
		sType       reflect.Type
		want        interface{}

		// getByteSlice returns the byte slice from the unmarshaled value, allowing the test to
		// inspect the addresses of the underlying byte array.
		getByteSlice func(interface{}) []byte
	}{
		{
			description: "struct with byte slice",
			data: docToBytes(fooBytes{
				Foo: []byte{0, 1, 2, 3, 4, 5},
			}),
			sType: reflect.TypeOf(fooBytes{}),
			want: &fooBytes{
				Foo: []byte{0, 1, 2, 3, 4, 5},
			},
			getByteSlice: func(val interface{}) []byte {
				return (*(val.(*fooBytes))).Foo
			},
		},
		{
			description: "bson.D with byte slice",
			data: docToBytes(D{
				{"foo", []byte{0, 1, 2, 3, 4, 5}},
			}),
			sType: reflect.TypeOf(D{}),
			want: &D{
				{"foo", primitive.Binary{Subtype: 0, Data: []byte{0, 1, 2, 3, 4, 5}}},
			},
			getByteSlice: func(val interface{}) []byte {
				return (*(val.(*D)))[0].Value.(primitive.Binary).Data
			},
		},
		{
			description: "struct with custom byte slice type",
			data: docToBytes(fooMyBytes{
				Foo: myBytes{0, 1, 2, 3, 4, 5},
			}),
			sType: reflect.TypeOf(fooMyBytes{}),
			want: &fooMyBytes{
				Foo: myBytes{0, 1, 2, 3, 4, 5},
			},
			getByteSlice: func(val interface{}) []byte {
				return (*(val.(*fooMyBytes))).Foo
			},
		},
		{
			description: "bson.D with custom byte slice type",
			data: docToBytes(D{
				{"foo", myBytes{0, 1, 2, 3, 4, 5}},
			}),
			sType: reflect.TypeOf(D{}),
			want: &D{
				{"foo", primitive.Binary{Subtype: 0, Data: myBytes{0, 1, 2, 3, 4, 5}}},
			},
			getByteSlice: func(val interface{}) []byte {
				return (*(val.(*D)))[0].Value.(primitive.Binary).Data
			},
		},
		{
			description: "struct with primitive.Binary",
			data: docToBytes(fooBinary{
				Foo: primitive.Binary{Subtype: 0, Data: []byte{0, 1, 2, 3, 4, 5}},
			}),
			sType: reflect.TypeOf(fooBinary{}),
			want: &fooBinary{
				Foo: primitive.Binary{Subtype: 0, Data: []byte{0, 1, 2, 3, 4, 5}},
			},
			getByteSlice: func(val interface{}) []byte {
				return (*(val.(*fooBinary))).Foo.Data
			},
		},
		{
			description: "bson.D with primitive.Binary",
			data: docToBytes(D{
				{"foo", primitive.Binary{Subtype: 0, Data: []byte{0, 1, 2, 3, 4, 5}}},
			}),
			sType: reflect.TypeOf(D{}),
			want: &D{
				{"foo", primitive.Binary{Subtype: 0, Data: []byte{0, 1, 2, 3, 4, 5}}},
			},
			getByteSlice: func(val interface{}) []byte {
				return (*(val.(*D)))[0].Value.(primitive.Binary).Data
			},
		},
		{
			description: "struct with primitive.ObjectID",
			data: docToBytes(fooObjectID{
				Foo: primitive.ObjectID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
			}),
			sType: reflect.TypeOf(fooObjectID{}),
			want: &fooObjectID{
				Foo: primitive.ObjectID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
			},
			getByteSlice: func(val interface{}) []byte {
				return (*(val.(*fooObjectID))).Foo[:]
			},
		},
		{
			description: "bson.D with primitive.ObjectID",
			data: docToBytes(D{
				{"foo", primitive.ObjectID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}},
			}),
			sType: reflect.TypeOf(D{}),
			want: &D{
				{"foo", primitive.ObjectID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}},
			},
			getByteSlice: func(val interface{}) []byte {
				oid := (*(val.(*D)))[0].Value.(primitive.ObjectID)
				return oid[:]
			},
		},
		{
			description: "struct with primitive.DBPointer",
			data: docToBytes(fooDBPointer{
				Foo: primitive.DBPointer{
					DB:      "test",
					Pointer: primitive.ObjectID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
				},
			}),
			sType: reflect.TypeOf(fooDBPointer{}),
			want: &fooDBPointer{
				Foo: primitive.DBPointer{
					DB:      "test",
					Pointer: primitive.ObjectID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
				},
			},
			getByteSlice: func(val interface{}) []byte {
				return (*(val.(*fooDBPointer))).Foo.Pointer[:]
			},
		},
		{
			description: "bson.D with primitive.DBPointer",
			data: docToBytes(D{
				{"foo", primitive.DBPointer{
					DB:      "test",
					Pointer: primitive.ObjectID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
				}},
			}),
			sType: reflect.TypeOf(D{}),
			want: &D{
				{"foo", primitive.DBPointer{
					DB:      "test",
					Pointer: primitive.ObjectID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
				}},
			},
			getByteSlice: func(val interface{}) []byte {
				oid := (*(val.(*D)))[0].Value.(primitive.DBPointer).Pointer
				return oid[:]
			},
		},
	}

	for _, tc := range testCases {
		tc := tc // Capture range variable.
		t.Run(tc.description, func(t *testing.T) {
			t.Parallel()

			// Make a copy of the test data so we can modify it later.
			data := make([]byte, len(tc.data))
			copy(data, tc.data)

			// Assert that unmarshaling the input data results in the expected value.
			got := reflect.New(tc.sType).Interface()
			err := Unmarshal(data, got)
			noerr(t, err)
			assert.Equal(t, tc.want, got, "unmarshaled value does not match the expected value")

			// Fill the input data slice with random bytes and then assert that the result still
			// matches the expected value.
			_, err = rand.Read(data)
			noerr(t, err)
			assert.Equal(t, tc.want, got, "unmarshaled value does not match expected after modifying the input bytes")

			// Assert that the byte slice in the unmarshaled value does not share any memory
			// addresses with the input byte slice.
			assertDifferentArrays(t, data, tc.getByteSlice(got))
		})
	}
}

// assertDifferentArrays asserts that two byte slices reference distinct memory ranges, meaning
// they reference different underlying byte arrays.
func assertDifferentArrays(t *testing.T, a, b []byte) {
	// Find the start and end memory addresses for the underlying byte array for each input byte
	// slice.
	sliceAddrRange := func(b []byte) (uintptr, uintptr) {
		sh := (*reflect.SliceHeader)(unsafe.Pointer(&b))
		return sh.Data, sh.Data + uintptr(sh.Cap-1)
	}
	aStart, aEnd := sliceAddrRange(a)
	bStart, bEnd := sliceAddrRange(b)

	// If "b" starts after "a" ends or "a" starts after "b" ends, there is no overlap.
	if bStart > aEnd || aStart > bEnd {
		return
	}

	// Otherwise, calculate the overlap start and end and print the memory overlap error message.
	min := func(a, b uintptr) uintptr {
		if a < b {
			return a
		}
		return b
	}
	max := func(a, b uintptr) uintptr {
		if a > b {
			return a
		}
		return b
	}
	overlapLow := max(aStart, bStart)
	overlapHigh := min(aEnd, bEnd)

	t.Errorf("Byte slices point to the same the same underlying byte array:\n"+
		"\ta addresses:\t%d ... %d\n"+
		"\tb addresses:\t%d ... %d\n"+
		"\toverlap:\t%d ... %d",
		aStart, aEnd,
		bStart, bEnd,
		overlapLow, overlapHigh)
}
