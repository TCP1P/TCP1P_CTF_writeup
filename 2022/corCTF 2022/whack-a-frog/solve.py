import os
import turtle
import re

WIDTH = 56
HEIGHT = 35

data = os.popen("tshark -r whacking-the-froggers.pcap | grep /anticheat").read()

def getxy(dat) -> list:
    '''find all x and y coordinates in the data'''
    x = re.findall(r'x=(\d+)', dat)
    y = re.findall(r'y=(\d+)', dat)
    return x, y

def get_comands(dat) -> list:
    '''find all command in the data'''
    com = re.findall(r'(?<=event=).*(?= HT)', dat)
    return com

x, y = getxy(data)
comand = get_comands(data)
turtle.setup(WIDTH*100, HEIGHT*100)
turtle.goto(0, 0)

turtle.speed(10)

def pixel_method(pix, size):
    turtle.shape('circle')
    turtle.shapesize(size, size)
    mouse = "mouseup"
    for i in range(len(x)):
        if mouse == "mouseup":
            turtle.penup()
        elif mouse == "mousedown":
            x_pix = (int(x[i])//pix)
            y_pix = (int(y[i])//pix)
            turtle.goto((x_pix*pix)-300, (y_pix*pix))
            turtle.stamp()
        if comand[i] == 'mousedown':
            mouse = "mousedown"
        elif comand[i] == 'mouseup':
            mouse = "mouseup"
    while True:
        pass
    
def pen_method():
    mouse = "mouseup"
    for i in range(len(x)):
        if mouse == "mouseup":
            turtle.penup()
        elif mouse == "mousedown":
            turtle.pendown()
        if comand[i] == 'mousedown':
            mouse = "mousedown"
        elif comand[i] == 'mouseup':
            mouse = "mouseup"
        turtle.goto(int(x[i])-300, int(y[i]))
    while True:
        pass

pixel_method(7, size=0.1)
# pen_method()