#!/usr/bin/env python3
import asyncio
from asyncio import new_event_loop, gather, ensure_future
from aiohttp import TCPConnector, ClientSession as Csession
from os import system, name
from ujson import loads
import urllib3

from socket import getaddrinfo, socket, SOCK_STREAM, error
from tabulate import tabulate

from utils import usage, description, logo, paths as p_static
import argparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def create_connection(address, timeout=None,
                      source_address=None,
                      full_scan=False):
    """Connect to *address* and return the socket object.

    Convenience function.  Connect to *address* (a 2-tuple ``(host,
    port)``) and return the socket object.  Passing the optional
    *timeout* parameter will set the timeout on the socket instance
    before attempting to connect.  If no *timeout* is supplied, the
    global default timeout setting returned by :func:`getdefaulttimeout`
    is used.  If *source_address* is set it must be a tuple of (host, port)
    for the socket to bind as a source address before making the connection.
    A host of '' or port 0 tells the OS to use the default.
    """

    host, port = address
    err = None
    for res in getaddrinfo(host, port, 0, SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket(af, socktype, proto)
            if timeout:
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(sa)
            err = None
            return None

        except error as _:
            err = _
            if sock is not None:
                sock.close()
                print("Error acquired: ", err)
                if not full_scan:
                    return err

    if err is not None:
        print("Error acquired: ", err)
        return err
    else:
        raise error("getaddrinfo returns an empty list")


def argument_parser():
    parser = argparse.ArgumentParser(usage=usage, add_help=True, description=description)
    parser.add_argument('-t', '--token',
                        help='Default Authorization header value. Example: Authorization: Bearer 12345678', type=str)
    parser.add_argument('targets', metavar="-targets",
                        help='Targets, separated by comma. Example: [10.10.3.1, 10.10.3.2, 10.10.3.3]', type=str)
    parser.add_argument('-p', '--paths', help='API paths, separated by comma. '
                                              'Default is explained in utils.py. Example: ['
                                              '"/readyz/poststarthook/rbac/bootstrap-roles", ""/apis/storage.k8s.io"',
                        type=str)
    parser.add_argument('-r', '--resolve', help="Every not resolved DNS could have some addresses. With "
                                                "this option this tool could try to resolve all of them.", type=bool)

    args = parser.parse_args()
    args.targets = args.targets.split(",")
    args.paths = args.paths.split(",")
    return args


class K8s_info(object):
    valid = lambda x: all(p not in x.lower() for p in ["shutdown", "drop", "stop", "delete"])
    ports = {10250: ["unauth kubelet api", False], 10255: ["unauth kubelet api", False],
             10256: ["kube proxy daemon", False], 30576: ["kube proxy daemon", False],
             443: ["main server", False], 6443: ["main server", False], 9443: ["main server", False],
             53: ["kube dns daemon", False], 6061: ["monitor daemon", False], 8082: ["heapster", False],
             2379: ["etcd", False], 22623: ["OpenShift (RHOCP)", False]}
    sensitive_routes = {8082: ["/api/v1/model/namespaces/namespaces/", "/api/v1/model/nodes/"],
                        10255: ["/pods", "/stats", "metrics", "/spec"],
                        22623: ["/config/worker"], 6443: ["/", "/version"], 443: ["/", "/version"]}

    def __init__(self, token: str, resolve: bool, paths: list = [], targets: list = []):

        self.token = token
        self.paths: list = paths or p_static
        self.targets: list = targets
        self.resolve_addrs: bool = resolve

        self.api_routes: dict = {}
        self.native_routes: dict = {}
        self.available_ports: dict = {}
        self.routes_information: dict = {}

        self.to_api_scan: list = []

    async def _api_walkthrough(self, paths: list,
                               url=None, is_api: bool = False):

        if not paths: paths = self.paths
        _prepared_request_connector = TCPConnector(limit=120, limit_per_host=120, ssl=False, use_dns_cache=True)
        headers = {"Authorization": self.token}

        async with Csession(connector=_prepared_request_connector, headers=headers) as _prepared_request_session:
            for path in paths:
                if K8s_info.valid(path):
                    request_url = url + path
                    async with _prepared_request_session.request('GET', request_url) as resp:
                        resp_data = await resp.text()
                        try:
                            new_paths = loads(resp_data)
                            fobidden = False
                            if new_paths.get("message") and "forbidden" in new_paths["message"]:
                                fobidden = True
                            if resp.status != 403 or not fobidden:
                                if is_api:
                                    self._change_result_api(path, resp.status)
                                else:
                                    self.native_routes.update({path: resp.status})
                        except ValueError as e:
                            continue
                        else:
                            await self._new_paths_checker(new_paths, request_url, path)

    async def _new_paths_checker(self, new_paths: dict, current_url: str, current_path):
        new_paths_res = []
        if new_paths.get("resources"):
            for new_path in new_paths["resources"]:
                if new_path.get("namespaced") and new_path["namespaced"] is True:
                    if new_path.get("name") and new_path.get("verbs"):
                        self.api_routes.update({f"{current_path}/{new_path.get('name')}": [current_url]})
                        for verb in new_path["verbs"]:
                            if K8s_info.valid(verb):
                                new_paths_res.append(f"/{new_path['name']}/{verb}/")
                                self.api_routes[f"{current_path}/{new_path.get('name')}"] += [{verb: 403}]
                    else:
                        new_paths_res.append(f"/{new_path['name']}")
            if new_paths_res: await self._api_walkthrough(new_paths_res, current_url, is_api=True)

    def _change_result_api(self, path: str, result_access: int or str):
        path = path.split("/")
        search_key = "/".join(path[:-1])[1:]
        if len(path) > 3 and self.api_routes.get(search_key):
            self.api_routes[search_key][0][path[-1:]] = result_access

    async def run_tool(self):
        assert self._check_iport_available(), "No open ports available."
        assert (await self._check_routes()), "Nothing found. All secure."
        tabulated = []
        for port, info in self.routes_information.items():
            temp = ""
            for item in info:
                temp += f"{item[0]} {item[1]}\n"
            tabulated += [[port, temp]]
        print(tabulate(tabulated, headers=["Port", "Results"], tablefmt="grid"))

        if self.to_api_scan:
            for target in self.to_api_scan:
                tasks = [ensure_future(self._api_walkthrough(self.paths[paths:paths + 100], target)) for paths in
                         range(0, len(self.paths), 100)]
                await gather(*tasks)

    def _check_iport_available(self) -> bool:
        for target in self.targets:
            ports = []
            for port in K8s_info.ports.keys():
                err = create_connection((target, port), timeout=3, full_scan=self.resolve_addrs)
                if not err:
                    ports.append(port)
            self.available_ports.update({target: ports})
        return len(self.available_ports.keys()) > 0

    async def _check_routes(self):
        tasks = []
        for target, ports in self.available_ports.items():
            for port in ports:
                print(f"Target: {target} with opened {port} port. Testing for sensitive routes.")
                if not target.startswith("https://") or target.startswith("http://"): target = "https://" + target
                tasks.append(asyncio.ensure_future(self._routes_walkthrough(port, target)))
        if tasks:
            await asyncio.gather(*tasks)
            if self.routes_information:
                self.routes_information = dict(filter(lambda item: item[1], self.routes_information.items()))
                return True
        return False

    async def _routes_walkthrough(self, port: int, target: str):
        if K8s_info.sensitive_routes.get(port):
            self.routes_information[port] = []
            async with Csession(connector=TCPConnector(ssl=False, keepalive_timeout=3)) as session:
                for route in K8s_info.sensitive_routes[port]:
                    url = f"{target}:{port}{route}"
                    async with session.get(url) as resp:
                        if resp.status != 503:
                            self.routes_information[port] += [(url, resp.status)]
                            if (port == 6443 or port == 443) and len(route) == 1:
                                self.to_api_scan.append(f"{target}:{port}")

    @property
    def get_targets(self):
        assert self.targets, "Targets are not set"
        return self.targets

    @get_targets.setter
    def set_targets(self, targets_: list):
        assert targets_, "Targets are not set"
        assert isinstance(targets_, list), "Targets should be of type(list)"
        self.targets = targets_

    @property
    def get_resolve(self):
        assert self.resolve_addrs, "Resolve addrs are not set"
        return self.resolve_addrs

    @get_resolve.setter
    def set_resolve(self, resolve_):
        assert resolve_, "resolve_ argument is not set"
        assert isinstance(resolve_, bool), "resolve_ should be bool"
        self.resolve_addrs = resolve_

    def __str__(self):
        tabulated_data_native = [(key, val) for key, val in self.native_routes.items()]
        tabulated_data_api = []
        if self.api_routes:
            for route, info in self.api_routes.items():
                temp = [[route, info[0], []]]
                for items in info[1:]:
                    temp[0][2] += ["-".join([item[0], str(item[1])]) for item in list(items.items())]
                tabulated_data_api += [[temp[0][0], temp[0][1], "\n".join(temp[0][2])]]
        else:
            print("[-] Try to use token. This one does not have access nowhere")
        return tabulate(tabulated_data_api, headers=["API routes", "URL", "Results"], tablefmt="grid") + "\n" + \
               tabulate([*tabulated_data_native], headers=["Routes", "Results"], tablefmt="grid")

