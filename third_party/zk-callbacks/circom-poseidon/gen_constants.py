# Written by Andrei Kotliarov

import re

with open("poseidon_constants_old.circom") as f:
    data = f.read()

C_data = data.split("POSEIDON_C")[1].split("POSEIDON_M")[0]
M_data = data.split("POSEIDON_M")[1]

#match = re.findall(r't == ([0-9]+)\) \{\s+return ([\[\],0-9]+);', C_data, re.DOTALL)
C = {}
match = re.findall(r't == ([0-9]+)\) \{\s+return (.+?);', C_data, re.DOTALL)
for i, c in match:
    C[int(i)] = eval(c)

M = {}
match = re.findall(r't == ([0-9]+)\) \{\s+return (.+?);', M_data, re.DOTALL)
for i, c in match:
    M[int(i)] = eval(c)

with open("constants.py", "w") as f:
    f.write(f"{C = }\n")
    f.write(f"{M = }\n")
