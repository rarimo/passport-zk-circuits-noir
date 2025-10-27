if [ ! -d "../circuits" ]; then
    mkdir ../circuits
    echo "✅ Successful creation of circuit directory"
fi


echo "🔄 Starting passport processing"

node ./process_passport_lite.js

name=$(head -n 1 ../src/main.nr | sed 's/^\/\///')

echo "✅ Successful passport proccessing"

echo "ℹ️ Circuit name: $name"

if [ -d "../circuits/$name" ]; then
    echo "Do you want to override the existing directory '../circuits/$name'? Y/N"
    read answer
    if [ "$answer" = "Y" ]; then
        rm -r "../circuits/$name"
        mkdir "../circuits/$name"
        echo "✅ Directory '../circuits/$name' has been overridden."
    else
        echo "ℹ️ Directory '../circuits/$name' was not overridden."
        return
    fi
else
mkdir ../circuits/$name
fi

echo "🔄 Starting circuit compilation"

nargo compile

mv ../target/noir_dl.json ../circuits/$name/$name.json

echo "✅ Successful circuit compilation"

echo "🔄 Starting generation of the verification key"

bbvk --setup-path ./ultraPlonkTrustedSetup.dat --circuit-path ../circuits/$name/$name.json --output-path ../circuits/$name/$name.vk

xxd -r -p ../circuits/$name/$name.vk > ../circuits/$name/$name.tmp && mv ../circuits/$name/$name.tmp ../circuits/$name/$name.vk

echo "✅ Successful generation of the verification key"

echo "🔄 Starting generation of the verification contract"

bb contract -k ../circuits/$name/$name.vk -o ../circuits/$name/$name.sol

echo "✅ Successful generation of the verification contract"

echo "✅ All tasks has been finished ✅"
