import binascii


def hexa_to_deci(s: str) -> int:
    res = 0
    c = 1
    a = 0
    b = 0
    for i in range(0, len(s), 2):
        if ord(s[i]) > 60:
            a = 9 + 1 * int(chr(int(ord(s[i])) - 48))
        if ord(s[i]) < 60:
            a = int(s[i])
        if ord(s[i + 1]) < 60:
            b = int(s[i + 1])
        if ord(s[i + 1]) > 60:
            b = 9 + 1 * int(chr(int(ord(s[i + 1])) - 48))
        res += c * (a * 16 + b)
        c *= 256
    return res


def cal(fat, fir_clust):
    res = []
    while True:
        res.append(fir_clust)
        fir_clust = hexa_to_deci(fat[fir_clust * 8:(fir_clust + 1) * 8])
        if fir_clust == int('0x0fffffff', 16):
            break
    return res


if __name__ == '__main__':
    file_get_path = input("请输入文件路径：").split("/")
    file_hexadecimal = [str(binascii.hexlify(bytes(file_get_path[i], 'utf-8')))[2:-1] for i in range(len(file_get_path))]
    file_get_path[-1] = file_get_path[-1].split(".")[0]
    file_open = open(r'\\.\\' + file_get_path[0], 'rb')
    dbr = str(binascii.hexlify(file_open.read(512)))[2:-1]
    byte_per_sector = hexa_to_deci(dbr[22: 26])
    sector_per_clust = hexa_to_deci(dbr[26: 28])
    reserve_sector = hexa_to_deci(dbr[28: 32])
    fat_num = hexa_to_deci(dbr[32: 34])
    count_sector = hexa_to_deci(dbr[64: 72])
    sector_per_fat = hexa_to_deci(dbr[72: 80])
    rootclust = hexa_to_deci(dbr[88: 96])
    fir_sector = reserve_sector + fat_num * sector_per_fat
    clust = [rootclust]
    print("\n该文件名目录项信息:")
    for i in range(1, len(file_get_path)):
        name = str(binascii.hexlify(bytes(file_get_path[i].upper(), 'utf-8')))[2:-1]
        file_open.seek((fir_sector + (clust[0] - rootclust) * sector_per_clust) * byte_per_sector)
        print("数据起始扇区号:", (fir_sector + (clust[0] - rootclust) * sector_per_clust))
        s_sector = str(binascii.hexlify(file_open.read(sector_per_clust * byte_per_sector)))[2:-1]
        print("当前扇区:", s_sector[0:20], '...(此处省略后段)')
        print("文件名:", name)
        file_str = -1
        file_str = s_sector.find(name)
        print("文件名对应的字符串:", file_str)
        if file_str == -1:
            print("Not Found. Check your path.")
            exit(-1)
        fir_clust = hexa_to_deci(s_sector[file_str + 40:file_str + 44]) * pow(16, 4) + hexa_to_deci(s_sector[file_str + 52:file_str + 56])
        print("\n该文件的簇链:")
        print("首簇:", fir_clust)
        file_open.seek(reserve_sector * byte_per_sector)
        fat = str(binascii.hexlify(file_open.read(sector_per_clust * byte_per_sector)))[2:-1]
        clust = cal(fat, fir_clust)
        print("簇链:", clust)
    print("\n拼接新文件:")
    with open("cx2.txt", mode="w+", encoding="utf-8", newline="") as f:
        for i in clust:
            file_open.seek((fir_sector + (i - rootclust) * sector_per_clust) * byte_per_sector)
            content = str(binascii.hexlify(file_open.read(sector_per_clust * byte_per_sector)))[2:-1]
            v = binascii.unhexlify(content.encode()).decode().rstrip('\0')
            f.write(v)
        print("Success.")

    print("\n判断生成文件与原文件内容是否一致:")
    file_get_path_str = '/'.join(file_get_path) + '.txt'
    with open(file_get_path_str, 'r', encoding='utf-8') as g:
        pre_content = g.readlines()
    with open('cx2.txt', 'r', encoding='utf-8') as f:
        copy_content = f.readlines()
    if pre_content == copy_content:
        print("文件内容一致")
    else:
        print("文件内容不一致")


