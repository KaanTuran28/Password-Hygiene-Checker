# Password Hygiene Checker — Example Output

Both runs below used the real CLI against two synthetic demo passwords (never a real user password). The breach check hit the live Have I Been Pwned API in this environment.

## Example 1 — weak / reused password (`password123`)

- Length: 11
- Character classes used: lowercase, digit (2/4)
- Estimated entropy: ~56.9 bits
- Found in common password list: yes
- Strength score: 0/100
- **Verdict: Weak**

- Breach check: ⚠️ found in **2,266,543** known breaches (Have I Been Pwned)

## Example 2 — strong / unique password (`Str0ng!Unique#Pass2026`)

- Length: 22
- Character classes used: lowercase, uppercase, digit, symbol (4/4)
- Estimated entropy: ~144.5 bits
- Found in common password list: no
- Strength score: 100/100
- **Verdict: Strong**

- Breach check: not found in any known breach (Have I Been Pwned)

> Note: your password is never stored or written to disk. Only this summary is saved.
