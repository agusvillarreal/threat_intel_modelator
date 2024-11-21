import click
from src.cli.commands.migrate import migrate_cli

def setup_cli():
    """Configurar CLI principal"""
    cli = click.Group()
    
    # Agregar comandos
    cli.add_command(migrate_cli)
    
    return cli

cli = setup_cli()

if __name__ == '__main__':
    cli()