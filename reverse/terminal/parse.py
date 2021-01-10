with open("dump2", "w") as ptr:
    with open("dump", "r") as f:
        for line in f:
            tokens = line.strip().split(" ")
            for i in range(1, 5):
                ptr.write(tokens[i])
