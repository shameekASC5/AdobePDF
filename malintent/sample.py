import keyboard

hotkeyUp = "1"
hotkeyDown = "2"

def Increase():
    print("Function has been executed with hotkey r")

keyboard.add_hotkey(hotkeyDown,Increase)