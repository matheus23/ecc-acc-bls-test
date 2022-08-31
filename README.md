# Playing with Elliptic Curve Accumulators

Don't use this of course!

I'm playing with something to understand it better.

What follows are my notes on how they work. They're essentially all taken from [this page](https://asecuritysite.com/zero/witness), but with all typos fixed.

## Equations

Using the bls12-381 curve(s) with the two cyclic groups $\mathbb{G}_1$ and $\mathbb{G}_2$.

We will generate the keypair in $\mathbb{G}_2$ and the accumulator in $\mathbb{G}_1$, because $\mathbb{G}_1$ is faster to do compuation on, and we assume we'll do more computation for accumulation. This can be flipped around if this assumption is incorrect.

$G_1$ is the base point for $\mathbb{G}_1$, $G_2$ is the base point for $\mathbb{G}_2$.

We use a dot for the group operation: $A.B$

We use juxtaposition for scalar multiplication: $s G_1$ is $s$ times $G_1$ operated on itself. $3 G_1$ is $G_1.G_1.G_1$

Generate a 32-byte secret key scalar $sk$. The according public key is

$$pk = sk G_2$$

We initialise the accumulator with:

$$a_0 = G_1$$

To add a 32-byte number $y_1$, we operate on the accumulator with:

$$a_1 = (y_1 + sk)a_0 = (y_1 + sk)G_1$$

To add $y_2$:

$$a_2 = (y_2 + sk)a_1 = (y_2 + sk)(y_1 + sk)a_0 = ((y_2 + sk)(y_1 + sk))G_1$$

To remove $y_1$ from $a_2$:

$$a_3 = \frac{1}{y_1 + sk}a_2 = \frac{1}{y_1 + sk}(y_2 + sk)(y_1 + sk)a_0 = (y_2 + sk)a_0$$

---

The public key and accumulator value can be public without revealing the accumulated values.

To generate a witness that an element $y_1$ is part of an accumulator $a$, you need access to the secret key $sk$. The witness $w$ is just the accumulator without the value $y_1$:

$$w = \frac{1}{y_1 + sk}a$$

To verify that a witness $w$ is a proof that an element $y_1$ is part of an accumulator $a$ with public key $pk$, verify the following pairing-based crypto statement:

$$e(w, y_1 G_2 . pk) \cdot e(-a, G_2) = 1$$

where $e(X, Y) \in \mathbb{G}_T$ is the pairing operation on $X \in \mathbb{G}_1$ and $Y \in \mathbb{G}_2$, $\mathbb{G}_T$ is the target group and $A \cdot B$ (with $A, B \in \mathbb{G}_T$) is the target group operation.

We can prove this equation given $a$ contains $y_1$, which would mean

$$a = (y_1 + sk)w$$

Taking:

$$e(w, y_1 G_2 . pk) \cdot e(-a, G_2) = 1$$

We use the pairing rule $e(X, A . B) = e(X, A) \cdot e(X, B)$:

$$e(w, y_1 G_2) \cdot e(w, pk) \cdot e(-a, G_2)$$

We can replace the public key with $sk G_2$:

$$e(w, y_1 G_2) \cdot e(w, sk G_2) \cdot e(-a, G_2)$$

And move over the $sk$ and $y_1$ using the pairing rule $e(A, s B) = e(s A, B)$:

$$e(y_1\ w, G_2) \cdot e(sk\ w, G_2) \cdot e(-a, G_2)$$

Now we combine the first two terms again:

$$e((y_1 + sk)w, G_2) \cdot e(-a, G_2)$$

Now, we recognize the definition of $a$ from above:

$$e(a, G_2) \cdot e(-a, G_2)$$

Which is the identity element $1 \in \mathbb{G}_T$.
