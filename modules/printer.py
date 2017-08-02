def archetypeName(index, depth):
    name = chr(ord('A') + (index % 26))
    index /= 26
    while index:
        name += chr(ord('A') + (index % 26))
        index /= 26
    if depth != 0:
        name += str(depth)
    return name
