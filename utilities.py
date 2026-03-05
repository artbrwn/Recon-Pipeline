import asyncio

def write_results_file( results, file_path):
    with open(file_path, "w") as file:
        file.write(results)

async def resolve_domain(dominio):
    loop = asyncio.get_event_loop()
    try:
        ip = await loop.getaddrinfo(dominio, None)
        return ip[0][4][0]
    except:
        return None

async def list_resolver(domains):
    tasks = [resolve_domain(d) for d in domains]
    return await asyncio.gather(*tasks)

def domains_to_ip(domains):
    domains = asyncio.run(list_resolver(domains))
    return domains