## Simple seed converter

### How to install
```bash
cargo install --git https://github.com/Rexagon/seed-converter.git
```

### How to use
```bash
# Generate new key
sc generate

# Derive keypair from seed
sc derive "my seed ...."

# Derive keypair from legacy seed file
cat my_seed.txt | sc derive -t legacy 

# Pipes
sc generate | sc derive
```
