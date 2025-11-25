


# class NotACall(Exception):
#     pass
#     # __add__ = exec


# try:
#     raise NotACall
# except NotACall as e:
#     print(e)
#     e + 'import os; os.system("ls")'



@exec
@input
def f(): pass