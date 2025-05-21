def run():
	import runpy

	from importlib_resources import files

	runpy.run_path(f"{files("jwt_tool").joinpath("jwt_tool.py")}", run_name="__main__")
