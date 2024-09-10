obj-m += checkpoint_project.o

all:
	# Make sure this is a tab, not spaces
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	# This line must also be indented with a tab
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
