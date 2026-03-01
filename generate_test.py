with open("big_test.py", "w") as f:
    for i in range(800):
        f.write(f"def func_{i}():\n")
        f.write("    return 'safe'\n\n")
