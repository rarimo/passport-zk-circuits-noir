package main

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

func ReadJSON(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, fmt.Errorf("failed to unmarshal json: %w", err)
	}
	return obj, nil
}

func RunCommand(command string) (string, string, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", command)
	} else {
		cmd = exec.Command("/bin/sh", "-c", command)
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()

	return stdoutBuf.String(), stderrBuf.String(), err
}

func GetSodASN1(path string, val interface{}) error {
	obj, err := ReadJSON(path)
	if err != nil {
		return err
	}
	sodRaw, found := obj["sod"]
	if !found {
		return fmt.Errorf("'sod' field not found in JSON")
	}
	sodStr, ok := sodRaw.(string)
	if !ok {
		return fmt.Errorf("'sod' field is not a string")
	}

	sodBytes, err := base64.StdEncoding.DecodeString(sodStr)
	if err != nil {
		return fmt.Errorf("failed to base64 decode sod: %w", err)
	}

	rest, err := asn1.Unmarshal(sodBytes, val)
	if err != nil {
		return fmt.Errorf("failed to ASN.1 decode sod: %w", err)
	}
	if len(rest) > 0 {
		fmt.Println("Warning: trailing bytes after ASN.1 decoding")
	}
	return nil
}

func GetDG1Bytes(path string) ([]byte, error) {
	obj, err := ReadJSON(path)
	if err != nil {
		return nil, err
	}
	dg1Raw, found := obj["dg1"]
	if !found {
		return nil, fmt.Errorf("'dg1' field not found in JSON")
	}
	dg1Str, ok := dg1Raw.(string)
	if !ok {
		return nil, fmt.Errorf("'dg1' field is not a string")
	}
	dg1Bytes, err := base64.StdEncoding.DecodeString(dg1Str)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode dg1: %w", err)
	}
	return dg1Bytes, nil
}

type ProverConfig struct {
	DG1        []byte `toml:"dg1"`
	SkIdentity string `toml:"sk_identity"`
}

func WriteProverToml(filepath string, dg1 []byte) error {
	config := ProverConfig{
		DG1:        dg1,
		SkIdentity: "1",
	}
	tomlBytes, err := toml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal toml: %w", err)
	}
	err = os.WriteFile(filepath, tomlBytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write toml file: %w", err)
	}
	return nil
}

func extractFields(s string) ([]string, error) {
	re := regexp.MustCompile(`Vec\(\[Field\(([^)]+)\), Field\(([^)]+)\), Field\(([^)]+)\)\]\)`)

	matches := re.FindStringSubmatch(s)
	if len(matches) != 4 {
		return nil, fmt.Errorf("expected 3 matches but got %d", len(matches)-1)
	}
	return matches[1:], nil
}

func process(jsonPath string) ([]string, error) {
	setupBB()

	dg1Bytes, err := GetDG1Bytes(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("error extracting dg1 bytes: %w", err)
	}
	fmt.Println("Successfully extracted dg1 bytes")

	err = WriteProverToml("../Prover.toml", dg1Bytes)
	if err != nil {
		return nil, fmt.Errorf("error writing Prover.toml: %w", err)
	}
	fmt.Println("Prover.toml written successfully")

	algo, err := getAlgo(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("error extracting hash algo: %w", err)
	}
	writeNoirCode(algo)
	fmt.Println("main.nr written successfully")

	stdout, stderr, err := RunCommand("cd .. && nargo execute")
	if err != nil {
		fmt.Println("Error:", err)
		fmt.Println("Stderr:", stderr)
	}
	fmt.Println("witness generated:", stdout)

	fields, err := extractFields(stdout)
	if err != nil {
		return nil, fmt.Errorf("error extracting fields: %w", err)
	}
	fmt.Println("Extracted fields:")
	for i, f := range fields {
		fmt.Printf("Field %d: %s\n", i+1, f)
	}

	_, stderr2, err := RunCommand("cd .. && bb prove -w ./target/register_identity_light.gz -b ./target/register_identity_light.json -o target/proof")
	if err != nil {
		fmt.Println("Error:", err)
		fmt.Println("Stderr:", stderr2)
	}
	fmt.Println("proof generated!")

	cmdFormat := "cd .. && bb verify -s ultra_honk -k ./keys/register_lite_%d.vk -p ./target/proof -v"

	command := fmt.Sprintf(cmdFormat, algo*8)

	_, stderr3, err := RunCommand(command)
	if err != nil {
		fmt.Println("Error:", err)
		fmt.Println("Stderr:", stderr3)
	}

	verified := false
	if parts := strings.Split(stderr3, "verified: "); len(parts) > 1 {
		verified = strings.TrimSpace(parts[1]) == "1"
	}
	fmt.Println("proof verified:", verified)

	if !verified {
		return nil, fmt.Errorf("proof verification failed")
	}

	return fields, nil
}

func printASN1Object(raw asn1.RawValue, level int) {
	indent := ""
	for i := 0; i < level; i++ {
		indent += "  "
	}
	fmt.Printf("%sTag: %d, Class: %d, Compound: %v\n", indent, raw.Tag, raw.Class, raw.IsCompound)
	fmt.Printf("%sBytes: %X\n", indent, raw.Bytes)
	if raw.IsCompound {
		rest := raw.Bytes
		for len(rest) > 0 {
			var child asn1.RawValue
			var err error
			rest, err = asn1.Unmarshal(rest, &child)
			if err != nil {
				fmt.Printf("%sError decoding child ASN.1: %s\n", indent, err)
				break
			}
			printASN1Object(child, level+1)
		}
	}
}

func getASN1ChildByPath(raw asn1.RawValue, path []int) (asn1.RawValue, error) {
	current := raw
	for _, idx := range path {
		if !current.IsCompound {
			return asn1.RawValue{}, fmt.Errorf("element at this level is not compound")
		}
		children := []asn1.RawValue{}
		rest := current.Bytes
		for len(rest) > 0 {
			var child asn1.RawValue
			var err error
			rest, err = asn1.Unmarshal(rest, &child)
			if err != nil {
				return asn1.RawValue{}, fmt.Errorf("failed to decode child: %w", err)
			}
			children = append(children, child)
		}
		if idx < 0 || idx >= len(children) {
			return asn1.RawValue{}, fmt.Errorf("index %d out of bounds, only %d children", idx, len(children))
		}
		current = children[idx]
	}
	return current, nil
}

func getAlgo(jsonPath string) (int, error) {
	var decodedASN1 asn1.RawValue

	err := GetSodASN1(jsonPath, &decodedASN1)
	if err != nil {
		return 0, fmt.Errorf("error decoding sod ASN.1: %w", err)
	}

	path := []int{0, 1, 0, 2, 1, 0}

	ec, err := getASN1ChildByPath(decodedASN1, path)
	if err != nil {
		return 0, fmt.Errorf("error accessing child: %w", err)
	}

	var ecDecoded asn1.RawValue
	rest, err := asn1.Unmarshal(ec.Bytes, &ecDecoded)
	if err != nil {
		return 0, fmt.Errorf("error decoding inner ASN.1: %w", err)
	}

	if len(rest) > 0 {
		fmt.Println("Warning: trailing bytes after inner ASN.1 decoding")
	}

	subpath := []int{2, 0, 1}
	targetChild, err := getASN1ChildByPath(ecDecoded, subpath)
	if err != nil {
		return 0, fmt.Errorf("error accessing inner child: %w", err)
	}

	algo := string(targetChild.Bytes)
	return len(algo), nil
}

func checkBBversion() bool {
	stdout, stderr, err := RunCommand("bb --version")
	if err != nil {
		fmt.Println("Error running bb --version:", err)
		fmt.Println("Stderr:", stderr)
		return false
	}
	version := strings.TrimSpace(stdout)
	fmt.Println("Detected bb version:", version)
	isCorrect := version == "0.66.0"
	fmt.Println("Is correct version:", isCorrect)
	return isCorrect
}

func setupBB() {
	if !checkBBversion() {
		fmt.Println("bb version incorrect or not found, installing bbup and bb...")
		_, stderr, err := RunCommand("bbup -v 0.66.0")
		if err != nil {
			fmt.Println("Error installing bb with bbup:", err)
			fmt.Println("Stderr:", stderr)
			fmt.Println("Installing bbup itself with curl...")
			_, stderr2, err2 := RunCommand(`curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install | bash`)
			if err2 != nil {
				fmt.Println("Error installing bbup:", err2)
				fmt.Println("Stderr:", stderr2)
				return
			}
			_, stderr3, err3 := RunCommand("bbup -v 0.66.0")
			if err3 != nil {
				fmt.Println("Error installing bb after bbup install:", err3)
				fmt.Println("Stderr:", stderr3)
				return
			}
		}
		fmt.Println("bb installed!")
	} else {
		fmt.Println("bb is already correct version.")
	}
}

func writeNoirCode(size int) error {
	path := "../src/main.nr"

	code := fmt.Sprintf(`use noir_dl::lite::register_identity_light;

fn main(
	dg1: [u8; 95],
	sk_identity: Field,
) -> pub (Field, Field, Field){
	let tmp = register_identity_light::<
		95,
		%d
	>(
		dg1, sk_identity);
	(tmp.0, tmp.1, tmp.2)
}
`, size)

	return os.WriteFile(path, []byte(code), 0644)
}

func main() {
	jsonPath := "tmp.json"
	fmt.Println(process(jsonPath))
}
