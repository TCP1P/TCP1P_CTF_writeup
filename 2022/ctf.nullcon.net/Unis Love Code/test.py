a="I"
# unicode character that produce the same result as the string "ADMIN"
# but is not a valid ASCII character
# and if you try to compare it with the string "ADMIN"
# it will return True
b = "\u0131"
# b = b.upper()
# print(bytes(b, "utf8"))
print(b)
print(a==b)

# payload username=admın
# http://www.unicode.org/Public/UNIDATA/CaseFolding.txt