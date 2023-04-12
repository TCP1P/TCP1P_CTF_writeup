---
title: 'BucketCTF 2023 | Writeup'
---

BucketCTF 2023
===

![Awesome](https://awesome.re/badge.svg)

![BucketCTF 2023](https://ctftime.org/media/cache/f3/65/f36574a6176cee6ee8c8df88e74833b3.png)

Play with the [TCP1P](https://ctftime.org/team/187248) team.

## MISC / Transmission

>The United States space force was one day containing routine tests on intergalactic light when they captured a random beam of light. **Senior General Hexy Pictora** believes this beam of light may actually be a new communication method used by aliens. Analyze the image to find out of any secrets are present.

[beamoflight.png](https://storage.ebucket.dev/beamoflight.png)

---
#### Analysis
We are given an image named `beamoflight.png`.
Running the exiftool command reveals the following information.
```
% exiftool beamoflight.png
ExifTool Version Number         : 12.50
File Name                       : beamoflight.png
Directory                       : .
File Size                       : 1397 bytes
File Modification Date/Time     : 2023:04:01 10:40:43+07:00
File Access Date/Time           : 2023:04:12 00:04:53+07:00
File Inode Change Date/Time     : 2023:04:12 00:04:51+07:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 724
Image Height                    : 1
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Image Size                      : 724x1
Megapixels                      : 0.000724
```
A digital image is represented by using a 2-D matrix of the color intestines at each grid points. The gray images use 8 bits, whereas colored utilizes 24 bits to describe the color model, such as RGB model as it has 3 channels R, G, B. In this technique pixel intensities are used to hide the information. As in here using MSB algorithm, so the Most Significant Bit of the color intensities at each grid point will be replaced by the message bit (When the text/ hidden message will be converted into bit stream).

So, here is the output of solver script:
:::spoiler Click to show details
```
:03:47: Alien Species 1: Greetings, unidentified spacecraft. This is the Andromedan Confederation. State your intentions.

02:03:50: Alien Species 2: Hello, Andromedan Confederation. This is the Sagittarian Alliance. We come in peace and wish to establish communication with your species.

02:03:53: Andromedan Confederation: We acknowledge your message, Sagittarian Alliance. We too come in peace. What is it that you wish to communicate about?

02:03:56: Sagittarian Alliance: We are interested in establishing a mutual defense agreement with your confederation. We have encountered hostile forces in this sector and believe that we can work together to protect our civilizations.

02:04:00: Andromedan Confederation: Your proposal is intriguing, Sagittarian Alliance. We will need to discuss this with our council and get back to you. In the meantime, can you tell us more about the hostile forces you have encountered?

02:04:04: Sagittarian Alliance: We have reason to believe that they are part of a larger coalition that seeks to dominate this sector of the galaxy. They are highly advanced and have already destroyed several of our outposts.

02:04:09: Andromedan Confederation: We are sorry to hear that. We too have had encounters with hostile forces in this sector. We will do everything in our power to assist you.

02:04:13: Sagittarian Alliance: Thank you, Andromedan Confederation. We have a message that we would like to send to you privately. Is there a secure channel that we can use?

02:04:18: Andromedan Confederation: Yes, we have a secure channel that we can open. We will send you the coordinates now.

02:04:22: Sagittarian Alliance: Thank you, Andromedan Confederation. We are sending the message now.

#####
bucket{d3c0d3_th3_png_f7c74c1dc7}
#####

02:04:25: Andromedan Confederation: Message received. We will keep this information confidential and use it to aid in our joint defense efforts.

02:04:29: Sagittarian Alliance: We trust that you will. Thank you for your cooperation, Andromedan Confederation. We look forward to working with you.

02:04:33: Andromedan Confederation: Likewise, Sagittarian Alliance. Until next time, safe travels.
```
:::

#### Solver script

> solver_Transmission.py :

:::spoiler Click to show details
```python=
from collections import OrderedDict
from PIL import Image

imFile = "beamoflight.png"
img = Image.open(imFile, 'r')
rawData = img.tobytes("raw", "RGB")
print(rawData.decode())
```
:::

:::success
Flag:`bucket{d3c0d3_th3_png_f7c74c1dc7}`
:::

---
## MISC / Drawing

>I caught a criminal drawing one of my art pieces. Im not sure what it is but the police don't want me to just wipe it out. Could you help out?

[bucket.webp](https://storage.ebucket.dev/bucket.webp)
[transform.webp](https://storage.ebucket.dev/transform.webp)

---
#### Analysis
We are given 2 images named `bucket.webp` and `transform.webp`.
Running the exiftool command reveals the following information.

![bucket.webp](https://storage.ebucket.dev/bucket.webp)
```
% exiftool bucket.webp 
ExifTool Version Number         : 12.50
File Name                       : bucket.webp
Directory                       : .
File Size                       : 1078 bytes
File Modification Date/Time     : 2023:04:06 04:03:06+07:00
File Access Date/Time           : 2023:04:08 00:26:39+07:00
File Inode Change Date/Time     : 2023:04:08 00:21:25+07:00
File Permissions                : -rw-r--r--
File Type                       : Extended WEBP
File Type Extension             : webp
MIME Type                       : image/webp
WebP Flags                      : EXIF, Alpha
Image Width                     : 512
Image Height                    : 512
Exif Byte Order                 : Little-endian (Intel, II)
Orientation                     : Horizontal (normal)
X Resolution                    : 0.99
Y Resolution                    : 0.99
Resolution Unit                 : inches
Software                        : paint.net 5.0.2
Exif Version                    : 0230
Color Space                     : sRGB
Exif Image Width                : 512
Exif Image Height               : 512
Interoperability Index          : R98 - DCF basic file (sRGB)
Interoperability Version        : 0100
Image Size                      : 512x512
Megapixels                      : 0.262
```
![transform.webp](https://storage.ebucket.dev/transform.webp)
```
% exiftool transform.webp 
ExifTool Version Number         : 12.50
File Name                       : transform.webp
Directory                       : .
File Size                       : 4.6 kB
File Modification Date/Time     : 2023:04:06 04:03:15+07:00
File Access Date/Time           : 2023:04:08 00:21:26+07:00
File Inode Change Date/Time     : 2023:04:08 00:21:25+07:00
File Permissions                : -rw-r--r--
File Type                       : Extended WEBP
File Type Extension             : webp
MIME Type                       : image/webp
WebP Flags                      : Alpha
Image Width                     : 512
Image Height                    : 512
Alpha Preprocessing             : Level Reduction
Alpha Filtering                 : Horizontal
Alpha Compression               : Lossless
VP8 Version                     : 0 (bicubic reconstruction, normal loop)
Horizontal Scale                : 0
Vertical Scale                  : 0
Image Size                      : 512x512
Megapixels                      : 0.262
```

**TL;DR**
Notice that `Alpha Compression : Lossless`. In images, there are two main compressions algorithms as `Lossy` Compression and `Lossless`Compression. In the `lossy` form, the amount of information is reduced before transmitting it. This reduction will be done by losing some redundant information. It means that the compressed image is not exactly like the original image. Joint photographic experts group `JPEG` is the image format that utilizes Lossy Compression. However, in `Lossless` compression the amount of information is not reduced from the target image. After the image is decompressed, all the information can be restored. However, graphical interchange format `GIF` and bitmap file `BMP` are image formats that utilize lossless compression.

LSB is the easiest and simplest algorithm. The cover image’s least significant bit (8-bit) is altered by the bit of the hidden message. It is utilized to insert hidden data in a cover image sometimes it is referred to as LSB Replacement. Because the LSB method depends on changing the redundant bits that are less important or significant with the secret information bits, particularly the rightmost bits will be replaced with the bits of the secret data because it does not affect the image’s quality.

So here's the result extracted LSB data using python script:
:::spoiler Click to show details
```
-- snip too long --
l}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6wevu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__3t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bflb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7v__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3c7vu70bfl}__7p1cb{93t6we0_kc3
```
:::

Then we can use [CyberChef](https://gchq.github.io/CyberChef/) to decode with this recipe:
```
Caesar_Box_Cipher(3)
Reverse('Character')
```
![load recipe](https://i.imgur.com/9oDozk2.png)
Result
![Flag Result](https://i.imgur.com/JpsdotO.png)

So lucky, get the firstblood.
![firstblood](https://i.imgur.com/my68rjp.png)


Reference:
* [webp](https://developers.google.com/speed/webp/gallery2)
* [Lossless and Transparency Encoding in WebP](https://blog.chromium.org/2011/11/lossless-and-transparency-encoding-in.html)
* [systematic overview of secure image steganography](http://download.garuda.kemdikbud.go.id/article.php?article=2158221&val=158&title=A%20systematic%20overview%20of%20secure%20image%20steganography)
* [Text extraction from image using LSB based steganography](https://www.geeksforgeeks.org/text-extraction-from-image-using-lsb-based-steganography/)

#### Solver script

> solver_Drawing.py :

:::spoiler Click to show details
```python=
from collections import OrderedDict
from PIL import Image

imFile = "transform.webp"
img = Image.open(imFile, 'r')
print("RGBA check:", img.mode == 'RGBA') # Identified R/G/B/A
rawData = img.tobytes("raw", "A") # Read data from R/G/B/A
print("Alpha data:", str(rawData)) # Print HEX Data
```
:::

:::success
Flag:`bucket{1_l0v3_w3bp_f77c069c7}`
:::

---
## MISC / Detective

>Watson: The criminal's wiped down the crime scene! How can we find them now? Holmes: Elementary, my dear Watson

[out.bmp](https://storage.ebucket.dev/out.bmp)

---
#### Analysis

We are given an blank white image named `out.bmp`.
Running the exiftool command reveals the following information.

```
% exiftool out.bmp 
ExifTool Version Number         : 12.50
File Name                       : out.bmp
Directory                       : .
File Size                       : 705 kB
File Modification Date/Time     : 2023:04:06 23:23:55+07:00
File Access Date/Time           : 2023:04:12 03:27:44+07:00
File Inode Change Date/Time     : 2023:04:12 03:27:40+07:00
File Permissions                : -rw-r--r--
File Type                       : BMP
File Type Extension             : bmp
MIME Type                       : image/bmp
BMP Version                     : Windows V3
Image Width                     : 787
Image Height                    : 298
Planes                          : 1
Bit Depth                       : 24
Compression                     : None
Image Length                    : 704472
Pixels Per Meter X              : 0
Pixels Per Meter Y              : 0
Num Colors                      : Use BitDepth
Num Important Colors            : All
Image Size                      : 787x298
Megapixels                      : 0.235
```
**TL;DR**
We know that an RGB image has three planes(Red, Green and Blue) each again having 8 bit planes. And each chracter when converted to ASCII and then to binary, occupies 7 bits. So this 7 bits can be embedded in 7 bit planes of the image, corresponding to each pixel of a plane(R or G or B). The 8th bit plane of the image is kept intact because it contains the highest details.

Here's the output from solver script:
![flag detective](https://i.imgur.com/7HYgOjq.png)

Reference:
* [BPCS-steganography](https://en.wikipedia.org/wiki/BPCS-steganography)
* [Bit plane](https://en.wikipedia.org/wiki/Bit_plane)

#### Solver script

> solver_Detective.py :

:::spoiler Click to show details
```python=
import cv2
import numpy as np

# Function to convert unit8 image to bitstream array
def int2bitarray(img):
    arr = []
    for i in range(img.shape[0]):
        for j in range(img.shape[1]):
            arr.append(np.binary_repr(img[i][j], width=8))
    return arr

# read image convert to bit stream
img = cv2.imread('out.bmp',0)
arr = np.array(int2bitarray(img))
arr = arr.reshape(img.shape)

plane = np.zeros((img.shape))
for k in range(0,8):
    for i in range(arr.shape[0]):
        for j in range(arr.shape[1]):
            plane[i,j]=int(arr[i,j][k])
    cv2.imwrite('file-'+str(7-k)+'.png',plane*255)
    print('bit plane '+str(7-k)+' done!')
```
:::

:::success
Flag:`bucket{r3plAc3_c0L0Rs!!}`
:::

---
## MISC / Image-2

>You can almost see the flag.

[mrxbox98.png](https://storage.ebucket.dev/mrxbox98.png)

---
#### Analysis

We are given an `png` image named `mrxbox98.png`.
![mrxbox98.png](https://storage.ebucket.dev/mrxbox98.png)
Running the exiftool command reveals the following information.
```
% exiftool mrxbox98.png 
ExifTool Version Number         : 12.50
File Name                       : mrxbox98.png
Directory                       : .
File Size                       : 36 kB
File Modification Date/Time     : 2023:04:06 23:08:09+07:00
File Access Date/Time           : 2023:04:12 22:48:26+07:00
File Inode Change Date/Time     : 2023:04:08 00:39:16+07:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 512
Image Height                    : 512
Bit Depth                       : 8
Color Type                      : RGB
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
SRGB Rendering                  : Perceptual
Gamma                           : 2.2
Pixels Per Unit X               : 3779
Pixels Per Unit Y               : 3779
Pixel Units                     : meters
Exif Byte Order                 : Big-endian (Motorola, MM)
Make                            : bucket(m3t4d4t4_4c53f444)
Resolution Unit                 : inches
Y Cb Cr Positioning             : Centered
Image Size                      : 512x512
Megapixels                      : 0.262
```

That's it. :tada:


:::success
Flag:`bucket(m3t4d4t4_4c53f444)`
:::

---
## MISC / minecraft

>I just started playing minecraft for my computer science class and forgot to remove a sign with my password before exiting the world. Could you please check what my password is.

[bucketctfMC.mcworld](https://storage.ebucket.dev/bucketctfMC.mcworld)

---
#### Analysis

We are given an `.mcworld` file. A zip archive that contains all the files needed to load a `Minecraft`: `Bedrock Edition` or `Minecraft Education world`, for example `.dat` and `.txt` files.
```
% file bucketctfMC.mcworld 
bucketctfMC.mcworld: Zip archive data, at least v4.5 to extract, compression method=deflate
```
Extracting `bucketctfMC.mcworld` using `7zip` will give this result
```
% 7za x bucketctfMC.mcworld 

7-Zip (a) [64] 17.04 : Copyright (c) 1999-2021 Igor Pavlov : 2017-08-28
p7zip Version 17.04 (locale=utf8,Utf16=on,HugeFiles=on,64 bits,4 CPUs x64)

Scanning the drive for archives:
1 file, 242175 bytes (237 KiB)

Extracting archive: bucketctfMC.mcworld

WARNINGS:
Headers Error

--
Path = bucketctfMC.mcworld
Type = zip
WARNINGS:
Headers Error
Physical Size = 242175

Everything is Ok

Archives with Warnings: 1

Warnings: 1
Files: 7
Size:       1247896
Compressed: 242175
```
```
% ls
db
level.dat
levelname.txt
bucketctfMC.mcworld
level.dat_old
world_icon.jpeg
```
Using `grep` command to find what we need.
```
% grep -Ri 'bucket' .
Binary file ./db/000003.log matches
```
Found `000003.log` file inside `db` directory. A log file is a computer-generated data file that contains information about usage patterns, activities, and operations within an operating system, application, server or another device. Log files show whether resources are performing properly and optimally.

Using `strings` and `grep` command we can find what we need inside the `log` file. Found the 1st part of flag.
```
% strings ./db/000003.log| grep bucket
bucket{1L0V3MIN
bucket{1L0V3MIN
bucket{1L0V3MIN
```
We noticed that the file is the output of the minecraft game. So, we tried to find other part of flag.
Here is the output from solver script.
```
% python3 solver.py
<re.Match object; span=(2871607, 3612575), match='bucket{1L0V3MIN\\n3CRAFT_1c330e9\\n105f1}\\x01\\x>
```

Reference:
* [minecraftfileextensions](https://learn.microsoft.com/en-us/minecraft/creator/documents/minecraftfileextensions)


#### Solver script

> solver_minecraft.py :

:::spoiler Click to show details
```python=
import re

file = open("db/000003.log", 'rb').read()
finding = re.search(r"bucket{(.*)}", str(file))
print(finding)
```
:::

:::success
Flag:`bucket{1L0V3MIN3CRAFT_1c330e9105f1}`
:::

---

###### tags: `BucketCTF 2023` `Writeup` `Documentation`

# Our Team Writeup

`@__andre__` : https://hackmd.io/r-xDsHKUSjmxfmVf2N-9uA#BucketCTF-2023

`@daffainfo` : https://github.com/daffainfo/ctf-writeup/tree/main/Bucket%20CTF%202023

