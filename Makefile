C := c++
FLAGS := -Wall -Wextra -Werror
SRC := Snort_Alert_Response.cpp
OBJS := $(SRC:%.cpp=%.o)
NAME := S_A_R

all: $(NAME)

$(NAME): $(OBJS)
	@$(C) $(FLAGS) $(OBJS) -o $(NAME)
	@echo "\033[1;32m$(NAME) \033[1;32mhas been compiled\033[0;37m"

%.o: %.cpp
	@$(C) $(FLAGS) -c $< -o $@

clean:
	@rm -f $(OBJS)
	@echo "\033[1;32mThe object files have been removed\033[0;37m"

fclean: clean
	@rm -f *_S_A_R.log
	@rm -f $(NAME)
	@echo "\033[1;32mThe object files and the program have been removed\033[0;37m"

re: fclean all