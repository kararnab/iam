package password_test

import (
	"context"
	"fmt"
	"strings"

	"github.com/kararnab/iam/v2/password"
)

func ExampleNewArgon2id() {
	ctx := context.Background()
	h, _ := password.NewArgon2id(password.DefaultParams, 0)

	encoded, _ := h.Hash(ctx, "correct horse battery staple")
	fmt.Println(strings.HasPrefix(encoded, "$argon2id$v=19$m=19456,t=2,p=1$"))

	ok, _ := h.Verify(ctx, "correct horse battery staple", encoded)
	bad, _ := h.Verify(ctx, "wrong", encoded)
	fmt.Println(ok, bad, h.NeedsRehash(encoded))
	// Output:
	// true
	// true false false
}
