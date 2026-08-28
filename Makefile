NAME   = ft_nmap
CC     = cc
CFLAGS = -Wall -Wextra -Werror

SRC    = main.c args.c utils.c pcap_utils.c tcp.c udp.c scan.c scan_types.c output.c \
         services.c
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

test: all
	./run_tests.sh

docker:
	docker build -t ft_nmap .

docker-shell: docker
	docker run -it --rm --cap-add=NET_RAW --cap-add=NET_ADMIN --entrypoint bash ft_nmap

.PHONY: all clean fclean re test docker docker-shell
