# Decode Android FinFisher 2019 obfuscated strings
# Esther Onfroy a.k.a U+039b - *@0x39b.fr (https://twitter.com/u039b)

from strings import STRINGS


def decode_array(encoded, index):
    mask = [102, 101, 100, 99, 98, 97, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48]
    if index % 2 == 0:
        mask = [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102]

    decoded = []
    counter = 0
    for e in encoded:
        decoded.append(chr(e ^ mask[counter % len(mask)]))
        counter += 1

    return ''.join(decoded)


def decode_string(strings, class_name, index):
    if class_name not in strings:
        return ''

    encoded = strings[class_name][index]
    return decode_array(encoded, index)


if __name__ == '__main__':
    a = [
        [0x1F, 67, 0x5F, 68, 68, 27, 69, 0x5F],
        [73, 1, 5, 23, 3, 78, 85, 87, 84, 87, 89, 27, 71, 0x5F, 65, 0x1F, 21, 28, 74, 2, 18, 10],
        [81, 0x5F, 86, 65, 91, 92, 82, 25, 91, 86, 15, 22, 6, 10, 17, 72, 0x73, 94, 92, 71, 81, 77, 66],
        [1, 0, 16, 51, 3, 2, 82, 89, 80, 83, 120, 85, 93, 83, 86, 85, 20],
        [81, 0x5F, 86, 65, 91, 92, 82, 25, 91, 86, 15, 22, 6, 10, 17, 72, 0x40, 92, 28, 99, 85, 86, 93, 86, 0x5F, 92,
         44, 3, 13, 5, 2, 3, 66],
        [1, 0, 16, 51, 3, 2, 82, 89, 80, 83, 0x7C, 90, 85, 93],
        [83, 94, 0x5F, 29, 93, 91, 69, 67, 89, 85, 13, 7, 17],
        [7, 11, 0, 17, 13, 8, 93, 22, 84, 89, 91, 0x40, 86, 92, 69, 30, 22, 8, 74, 51, 3, 2, 82, 89, 80, 83, 0x7C, 90,
         85, 93],
        [81, 65, 66, 0x5F, 93, 86, 87, 67, 81, 86, 15, 43, 13, 2, 10],
        [7, 11, 0, 17, 13, 8, 93, 22, 84, 89, 91, 0x40, 86, 92, 69, 30, 22, 8, 74, 34, 18, 17, 85, 81, 84, 87, 65, 93,
         92, 92, 120, 94, 0, 10],
        [67, 94, 71, 65, 87, 80, 0x72, 94, 74],
        [73, 23, 9, 20, 16, 0x4F, 74, 80],
        [83, 94, 0x5F, 29, 93, 91, 69, 67, 89, 85, 13, 7, 17],
        [9, 23, 3, 77, 26, 12, 85, 72, 66, 69, 93, 26, 69, 1],
        [0x1F, 67, 0x5F, 29, 71, 93],
        [73, 7, 5, 16, 7, 0x4F, 88, 72, 92],
        [0x1F, 66, 75, 0x40, 0x40, 80, 91, 24],
    ]
    for i in range(len(a)):
        print(decode_array(a[i], i))
    # for class_name in STRINGS:
    #     for i in range(len(STRINGS[class_name])):
    #         decoded_string = decode_string(STRINGS, class_name, i).strip()
    #         print(f'{class_name};{i};"{decoded_string}"')
