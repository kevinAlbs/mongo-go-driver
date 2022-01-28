# If needed: 
# go clean -cache -testcache
export PKG_CONFIG_PATH=/Users/kevin.albertson/Desktop/install/libmongocrypt/lib/pkgconfig
export DYLD_LIBRARY_PATH=/Users/kevin.albertson/Desktop/install/libmongocrypt/lib/
export LD_LIBRARY_PATH=/Users/kevin.albertson/Desktop/install/libmongocrypt/lib/

go test -v -tags cse -count=1 ./mongo/integration -run TestFLE20CreateCollection