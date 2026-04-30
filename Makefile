NAME   = ft_nmap
CC     = cc
CFLAGS = -Wall -Wextra -Werror

SRC    = main.c args.c utils.c pcap_utils.c tcp.c udp.c scan.c output.c
OBJ    = $(SRC:.c=.o)
LIBS   = -lpcap -lpthread -lm

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(NAME) $(LIBS)

%.o: %.c ft_nmap.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
