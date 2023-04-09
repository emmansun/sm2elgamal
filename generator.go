//go:build ignore

package main

import (
	"crypto/elliptic"
	"log"
	"math/big"
	"os"

	"github.com/emmansun/gmsm/sm2"
)

// ~1 minute, 65m data
func main() {
	size := 1 << 21
	var bin []byte
	sm2Curve := sm2.P256()
	log.Println("start...")
	for i := 1; i < size; i++ {
		x, y := sm2Curve.ScalarBaseMult(big.NewInt(int64(i)).Bytes())
		bin = append(bin, elliptic.MarshalCompressed(sm2Curve, x, y)...)
	}
	err := os.WriteFile("sm2_lookup_table.bin", bin, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("end.")
}
