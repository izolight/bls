package main

import (
	"crypto/sha256"
	"fmt"
	"github.com/Nik-U/pbc"
)

type messageData struct {
	message string
	signature []byte
}

func main() {
	params := pbc.GenerateA(160, 512)
	pairing := params.NewPairing()
	g := pairing.NewG2().Rand()

	sharedParams := params.String()
	fmt.Println("Shared Params:\n", sharedParams)
	sharedG := g.Bytes()
	fmt.Printf("Shared G: %s\n", g.String())
	fmt.Println()

	messageChannel := make(chan *messageData)
	keyChannel := make(chan []byte)
	finished := make(chan bool)

	go alice(sharedParams, sharedG, messageChannel, keyChannel, finished)
	go bob(sharedParams, sharedG, messageChannel, keyChannel, finished)

	<-finished
	<-finished
}

func alice(sharedParams string, sharedG []byte, messageChannel chan *messageData, keyChannel chan []byte, finished chan bool) {
	pairing, _ := pbc.NewPairingFromString(sharedParams)
	g := pairing.NewG2().SetBytes(sharedG)
	privKey := pairing.NewZr().Rand()
	fmt.Printf("Alice sk -> Random: %s\n", privKey)
	pubKey := pairing.NewG2().PowZn(g, privKey)
	fmt.Printf("Alice pk = sk x G: %s\n", pubKey)
	keyChannel <- pubKey.Bytes()

	message := "some text to sign"
	fmt.Printf("Alice message m: %s\n", message)
	h := pairing.NewG1().SetFromStringHash(message, sha256.New())
	fmt.Printf("Alice H(m): %s\n", h)
	signature := pairing.NewG2().PowZn(h, privKey)
	fmt.Printf("Alice S = sk x H(m): %s\n", signature)
	fmt.Println()

	messageChannel <- &messageData{message: message, signature: signature.Bytes()}

	finished <- true
}

func bob(sharedParams string, sharedG []byte, messageChannel chan *messageData, keyChannel chan []byte, finished chan bool) {
	pairing, _ := pbc.NewPairingFromString(sharedParams)
	g := pairing.NewG2().SetBytes(sharedG)
	pubKey := pairing.NewG2().SetBytes(<-keyChannel)
	fmt.Printf("Bob receives Alice pk: %s\n", pubKey)
	data := <-messageChannel
	fmt.Printf("Bob receives m: %s\n", data.message)
	signature := pairing.NewG1().SetBytes(data.signature)
	fmt.Printf("Bob receives S: %s\n", signature)

	h := pairing.NewG1().SetFromStringHash(data.message, sha256.New())
	fmt.Printf("Bob generates H(m): %s\n", h)
	temp1 := pairing.NewGT().Pair(h, pubKey)
	fmt.Printf("Bob generates e(h, pk): %s\n", temp1)
	temp2 := pairing.NewGT().Pair(signature, g)
	fmt.Printf("Bob generates e(S, g): %s\n", temp2)
	fmt.Println()

	if !temp1.Equals(temp2) {
		fmt.Println("Signature check failed")
	} else {
		fmt.Println("Signature verified successfully")
	}

	finished <- true
}