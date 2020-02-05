$computer_name = <computername>
$username = <username>
$pipe_atctl_sb =  {
    try{
        $npipe= new-object System.IO.Pipes.NamedPipeClientStream(".", 
                                                            'atctl', 
                                [System.IO.Pipes.PipeDirection]::InOut,
                                [System.IO.Pipes.PipeOptions]::None,                [System.Security.Principal.TokenImpersonationLevel]::Impersonation)
        $npipe.Connect(5000)
        'Connected to ATCTL RPC Backdoor Pipe'
        $npipe.Close()
    } Catch [TimeoutException] {
        'RPC Backdoor Pipe Not Found'
    }
}
$pipe_pnrsvc_sb =  {
    try{
        $npipe= new-object System.IO.Pipes.NamedPipeClientStream(".", 
                                                            ‘pnrsvc’, 
                                    [System.IO.Pipes.PipeDirection]::InOut,
                                    [System.IO.Pipes.PipeOptions]::None,
        [System.Security.Principal.TokenImpersonationLevel]::Impersonation)
        $npipe.Connect(5000)
        'Connected to PNRSVC RPC Backdoor Pipe'
        $npipe.Close()
    } Catch [TimeoutException] {
        'RPC Backdoor Pipe Not Found'
    }
}
Invoke-Command -computername $computer_name -credential $username $pipe_atctl_sb
Invoke-Command -computername $computer_name -credential $username $pipe_pnrsvc_sb
