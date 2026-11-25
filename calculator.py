a = int(input("Enter first number: "))
b = int(input("Enter second number: "))
op = input("Enter operation: ")

print(a, op, b, "=", end=" ") # I learned this end= trick to avoid repeating code!

if op == "+":
    print(a + b)
elif op == "-":
    print(a - b)
elif op == "*":
    print(a * b)
elif op == "/":
    print(a / b)
elif op == "**":
    print(a ** b)