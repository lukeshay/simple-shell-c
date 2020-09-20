CC = gcc
CXX = g++
ECHO = echo
RM = rm -f

TERM = "\"S2019\""

CFLAGS = -Wall -funroll-loops -DTERM=$(TERM) -ggdb3 -DNDEBUG -std=c11 -pedantic
CXXFLAGS = -Wall -funroll-loops -DTERM=$(TERM) # -ggdb3 -DNDEBUG

LDFLAGS = -lncurses

BIN = shell352
OBJS = main.o


all: $(BIN) # etags

$(BIN): $(OBJS)
	@$(ECHO) Linking $@
	@$(CXX) $^ -o $@ $(LDFLAGS)

-include $(OBJS:.o=.d)

%.o: %.c
	@$(ECHO) Compiling $<
	@$(CC) $(CFLAGS) -MMD -MF $*.d -c $<

%.o: %.cpp
	@$(ECHO) Compiling $<
	@$(CXX) $(CXXFLAGS) -MMD -MF $*.d -c $<

.PHONY: all clean clobber # etags

clean:
	@$(ECHO) Removing all generated files
	@$(RM) *.o $(BIN) *.d TAGS core vgcore.* gmon.out *.dSYM

clobber: clean
	@$(ECHO) Removing backup files
	@$(RM) *~ \#* *pgm

# etags:
# 	@$(ECHO) Updating TAGS
# 	@etags *.[ch] *.cpp