#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <cstdlib>
#include <unistd.h>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <csignal>


void print_name(void)
{
    std::cout << "\033[1;35m┏┓        ┏┓┓      ┳┓            " << std::endl;
    std::cout << "┗┓┏┓┏┓┏┓╋ ┣┫┃┏┓┏┓╋ ┣┫┏┓┏┏┓┏┓┏┓┏┏┓" << std::endl;
    std::cout << "┗┛┛┗┗┛┛ ┗━┛┗┗┗ ┛ ┗━┛┗┗ ┛┣┛┗┛┛┗┛┗ " << std::endl;
    std::cout << "                        ┛         " << std::endl;
    std::cout << "┓     ┏┓┓ ┏┓     •       " << std::endl;
    std::cout << "┣┓┓┏  ┣ ┃ ┃┃┏┓╋┏┓┓┏┓┓┏┏┳┓" << std::endl;
    std::cout << "┗┛┗┫  ┗┛┗┛┣┛┗┻┗┛ ┗┛┗┗┻┛┗┗" << std::endl;
    std::cout << "   ┛                      \033[0m" << std::endl;
}

std::string getCurrentDateTime()
{
    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d_%H-%M-%S");
    return oss.str();
}

std::string extractIPAddress(const std::string& input)
{
    size_t colonPos = input.find(':');
    
    if (colonPos != std::string::npos)
        return (input.substr(0, colonPos));
    
    return (input);
}

void signalHandler(int signum)
{
    (void)signum;
    std::cout << "\n\033[1;35m(SIGINT) Exiting...\033[0m" << std::endl;
    exit(0);
}

int main()
{
    print_name();
    signal(SIGINT, signalHandler);
    std::string datetime = getCurrentDateTime();
    std::string logfile = datetime + "_S_A_R.log";
    std::string snort_log = "/var/log/snort/alert";
    std::string alert_keywords[] = {"SYN_Flood", "UDP_Flood", "Excessive_HTTP", "Excessive_HTTPS"};
    std::ifstream file(snort_log.c_str());

    if (!file.is_open())
    {
        std::cerr << "\033[1;31mError opening file: \033[0;37m" << snort_log <<  "\033[0m" << std::endl;
        return (1);
    }
    else
        std::cout << "\033[1;32mLog file \033[1;37m" << snort_log << "\033[1;32m opened successfully \033[0m" << std::endl;

    file.seekg(0, std::ios::end);

    std::string line;
    std::ofstream l_file(logfile);

    if (!l_file.is_open())
    {
        std::cerr << "\033[1;31mError opening file: Make sure to run the S_A_R with sudo" << logfile << "\033[0m" << std::endl;
        return (1);
    }
    std::regex ip_pattern(R"((\d{1,3}\.){3}\d{1,3}(:\d{1,5})?)");

    int counter = 0;
    while (true)
    {
        if (std::getline(file, line))
        {
            if (line.empty())
                continue;
            counter ++;
            std::cout << "\033[1;33mA NEW ALERT IS HERE !!! ALERT COUNTER IS : \033[1;37m" << counter << "\033[0m" << std::endl;

            for (const auto& alert_keyword : alert_keywords)
            {
                if (line.find(alert_keyword) != std::string::npos)
                {
                    std::smatch match;
                    if (std::regex_search(line, match, ip_pattern) && !match.empty())
                    {
                        std::string ip = extractIPAddress(match.str(0));
                        std::cout << "\033[1;32mBlocking IP: \033[1;37m" << ip << "\033[1;32m due to alert: \033[1;37m" << alert_keyword << "\033[0m" << std::endl;
                        std::string command = "iptables -A INPUT -s " + ip + " -j DROP";
                        std::system(command.c_str());
                        l_file << getCurrentDateTime() << " Blocking IP: " << ip << " due to alert: " << alert_keyword << std::endl;
                    }
                    break;
                }
            }
        }
        else if (file.eof())
        {
		file.clear();
		file.seekg(0, std::ios::cur);
		usleep(500);
        }
        else
        {
            std::cerr << "\033[1;31mError reading file\033[0;37m" << std::endl;
            break;
        }
    }

    return (0);
}
