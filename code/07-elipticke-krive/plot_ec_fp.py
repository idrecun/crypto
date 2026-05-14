import matplotlib.pyplot as plt

p = 61
a, b = -1, 1

xs, ys = [], []
for x in range(p):
    rhs = (x * x * x + a * x + b) % p
    for y in range(p):
        if (y * y) % p == rhs:
            xs.append(x)
            ys.append(y)

fig, ax = plt.subplots(figsize=(6, 6))
ax.scatter(xs, ys, s=22, color="C0", zorder=3)
ax.set_title(r"$y^2 = x^3 - x + 1 \;(\mathrm{mod}\;61)$")
ax.set_xlabel("x")
ax.set_ylabel("y")
ax.set_xlim(-2, p + 1)
ax.set_ylim(-2, p + 1)
ax.set_aspect("equal")
ax.grid(True, alpha=0.5)
ax.axhline(0, color="gray", linewidth=0.8)
ax.axvline(0, color="gray", linewidth=0.8)

fig.tight_layout()
fig.savefig("/home/idrecun/repos/crypto/book/src/images/ec_fp.png", dpi=150)
print(f"points: {len(xs)}")
