---
layout: post
title:  "Solver-Password In Haystack"
categories: jekyll update
---

Ini merupakan challange CTF McAfee ATR Hax 2021 dengan kategori forensik yang berjudul **`Password in Haystack`**. Kita disediakan sebuah [file teks](https://github.com/advanced-threat-research/ATR_HAX_CTF/tree/master/forensics/password_in_a_haystack/challenge) yang berisi ribuan string password dan kita diminta untuk mencari password yang memenuhi beberapa kriteria antara lain:

- Setiap password harus merupakan karakter sepanjang 6-12 karakter yang _printable_
- Setiap password harus berisi setidaknya 3 buah angka
- Password tidak boleh berisi 3 karakter berurutan dari username (termasuk username yang tersusun secara terbalik)

Dari aturan tersebut kita diberikan sebuah username `steve557` dan apabila mengacu pada ketentuan nomor tiga password yang kita cari tidak boleh berasal 3 karakter dari "steve557" dan "755evets" (username secara terbalik).

Dari tiga aturan tersebut dapat kita simpulkan bahwa password yang memenuhi aturan adalah password yang memiliki tiga kriteria tersebut sekaligus. Oleh karena itu challenge ini dapat diselesaikan dengan operasi himpunan sederhana menggunakan pemrograman. Berikut adalah solver yang berhasil saya gunakan untuk menyelesaikan challenge ini.


```py
user="steve557"
consecutive=["ste", "tev" ,"eve", "ve5" ,"e55", "557"]
not_allowed = consecutive + [x[::-1] for x in consecutive]
 

def rule1(pwd):
    return ((6<=len(pwd)<=12) and pwd.isprintable())
def rule2(pwd):
    num=""
    for c in pwd:
        if(c.isnumeric()):
            num+=c
    unique=len(set(str(num)))
    return True if unique>=3 else False
def rule3(pwd):
    return all([str(x) not in str(pwd) for x in not_allowed])
 
 
if __name__ == "__main__":
    data=open("output.txt","r").read().split('\n')
    res1=set()
    res2=set()
    res3=set()
    for pwd in data:
        r1=rule1(pwd)
        if r1==True:
            res1.add(pwd)
        r2=rule2(pwd)
        if r2==True:
            res2.add(pwd)
        r3=rule3(pwd)
        if r3==True:
            res3.add(pwd)
    print(res1.intersection(res2).intersection(res3))
``` 