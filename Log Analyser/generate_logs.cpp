/*
 * generate_logs.cpp
 * Generates a realistic Nginx/Apache-style access log for testing.
 * Usage: ./generate_logs <num_lines> <output_file>
 *        ./generate_logs 5000000 server.log   # ~500 MB
 */
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <cstring>

static const char* METHODS[]  = {"GET","POST","PUT","DELETE","HEAD"};
static const char* PATHS[]    = {
    "/api/users","/api/orders","/api/products","/api/auth/login",
    "/api/auth/logout","/static/app.js","/static/style.css",
    "/health","/metrics","/api/search","/api/cart","/api/checkout",
    "/images/banner.jpg","/favicon.ico","/robots.txt"
};
static const char* STATUS[]   = {"200","200","200","200","200","201","204",
                                  "301","304","400","401","403","404","404",
                                  "429","500","502","503"};
static const int   LATENCY[]  = {5,12,18,25,40,60,80,120,200,350,500,800,1200,2500,5000};
static const char* UAS[]      = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14) Safari/17",
    "curl/7.88.1",
    "python-requests/2.31.0",
    "Go-http-client/1.1"
};

static const char* MONTHS[] = {"Jan","Feb","Mar","Apr","May","Jun",
                                "Jul","Aug","Sep","Oct","Nov","Dec"};

int main(int argc, char** argv) {
    int    nlines  = argc > 1 ? atoi(argv[1]) : 100000;
    const char* out = argc > 2 ? argv[2] : "server.log";

    FILE* f = fopen(out, "w");
    if (!f) { perror("fopen"); return 1; }

    srand(42);
    time_t base = 1700000000; // Nov 2023

    // A fixed pool of IPs (some more frequent = realistic)
    const char* IPS[] = {
        "10.0.1.5","10.0.1.22","192.168.2.10","203.0.113.44",
        "198.51.100.7","203.0.113.91","10.0.2.15","172.16.0.3",
        "198.51.100.55","203.0.113.12","10.10.10.10","192.0.2.8"
    };
    const int nips = sizeof(IPS)/sizeof(IPS[0]);
    const int nmet = sizeof(METHODS)/sizeof(METHODS[0]);
    const int npth = sizeof(PATHS)/sizeof(PATHS[0]);
    const int nst  = sizeof(STATUS)/sizeof(STATUS[0]);
    const int nlat = sizeof(LATENCY)/sizeof(LATENCY[0]);
    const int nua  = sizeof(UAS)/sizeof(UAS[0]);

    for (int i = 0; i < nlines; ++i) {
        time_t t   = base + (rand() % (60*60*24*30)); // 30-day window
        struct tm* tm = gmtime(&t);
        int sz     = 200 + rand() % 50000;
        int lat    = LATENCY[rand() % nlat] + rand() % 20;
        int stidx  = rand() % nst;

        // Nginx combined log format:
        // IP - - [day/Mon/Year:HH:MM:SS +0000] "METHOD /path HTTP/1.1" STATUS bytes latency_ms "referer" "ua"
        fprintf(f,
            "%s - - [%02d/%s/%04d:%02d:%02d:%02d +0000] \"%s %s HTTP/1.1\" %s %d %d \"-\" \"%s\"\n",
            IPS[rand() % nips],
            tm->tm_mday, MONTHS[tm->tm_mon], tm->tm_year+1900,
            tm->tm_hour, tm->tm_min, tm->tm_sec,
            METHODS[rand() % nmet],
            PATHS[rand() % npth],
            STATUS[stidx],
            sz, lat,
            UAS[rand() % nua]
        );
    }

    fclose(f);
    printf("Generated %d lines -> %s\n", nlines, out);
    return 0;
}
