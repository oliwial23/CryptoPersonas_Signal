# Written by Andrei Kotliarov

from textwrap import indent, dedent
from constants import C, M

FULL_ROUNDS = 8
PARTIAL_ROUNDS = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68]
MAX_INPUTS = 16

INDENT = '    '

indent_level = 0

def ind(text):
    global indent_level
    return indent_level * INDENT + text

def ind_in(text):
    global indent_level
    ret = ind(text)
    indent_level += 1
    return ret

def ind_out(text):
    global indent_level
    indent_level -= 1
    return ind(text)

def gen_ark():
    global indent_level

    ARK = ind_in("pub fn get_ark<F: PrimeField>(t: usize) -> Vec<Vec<F>> {\n")
    
    ARK += ind("")
    for t in range(2, 18):
        ARK += f"if t == {t} " + "{\n"
        indent_level += 1

        ARK += ind_in("vec![\n")
        for rnd in range(FULL_ROUNDS + PARTIAL_ROUNDS[t - 2]):
            ARK += ind_in("vec![\n")
            for i in range(t):
                key = C[t][rnd * t + i]
                ARK += ind(f'F::from_str("{key}").unwrap_or_else(|_| panic!("pepega")),\n')
            ARK += ind_out("],\n")
        ARK += ind_out("]\n")
        ARK += ind_out("} else ")

    ARK += "{\n"
    indent_level += 1
    ARK += ind('panic!("bad t value: {}", t);\n')
    ARK += ind_out("}\n")

    ARK += ind_out("}\n")
    return ARK

def gen_mds():
    global indent_level
    
    MDS = ind_in("pub fn get_mds<F: PrimeField>(t: usize) -> Vec<Vec<F>> {\n")

    MDS += ind("")
    for t in range(2, 18):
        MDS += f"if t == {t} " + "{\n"
        indent_level += 1

        MDS += ind_in("vec![\n")
        for row in M[t]:
            MDS += ind_in("vec![\n")
            for num in row:
                MDS += ind(f'F::from_str("{num}").unwrap_or_else(|_| panic!("pepega")),\n')
            MDS += ind_out("],\n")
        MDS += ind_out("]\n")
        MDS += ind_out("} else ")

    MDS += "{\n"
    indent_level += 1
    MDS += ind('panic!("bad t value: {}", t);\n')
    MDS += ind_out("}\n")
    MDS += ind_out("}\n")

    return MDS

def gen_constants_rs():
    global indent_level
    with open("src/lib.rs", "w") as f:
        f.write(dedent(f"""
            use ark_ff::PrimeField;

            use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;

            pub const PARTIAL_ROUNDS: &'static [usize] = &{PARTIAL_ROUNDS};

            pub fn get_poseidon_params<F: PrimeField>(
                rate: usize,
            ) -> PoseidonConfig<F> {{
                PoseidonConfig::new(
                    {FULL_ROUNDS},
                    PARTIAL_ROUNDS[rate - 1],
                    5,
                    get_mds(rate + 1),
                    get_ark(rate + 1),
                    rate,
                    1
                )
            }}

        """))


        OUT = gen_ark()
        OUT += "\n"
        OUT += gen_mds()

        print(OUT)

        f.write(OUT)
        
gen_constants_rs()
