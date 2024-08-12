package main_test

import (
	"fmt"
	"strconv"
	"testing"
)

func TestRoundtrip(t *testing.T) {
	num, err := strconv.Atoi("")
	fmt.Println(num, err)
}
