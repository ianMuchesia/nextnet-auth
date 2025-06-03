import { User } from '@/@types/user'
import React from 'react'


type NavbarProps = {
    user: User | null;
}
// This component is a simple Navbar that can be extended later


const Navbar: React.FC<NavbarProps> = ({ user }) => {
    return (
        <nav className="bg-gray-800 p-4">
            <div className="container mx-auto flex justify-between items-center">
                <div className="text-white text-lg font-bold">MyApp</div>
                <div className="space-x-4">
                    {user ? (
                        <>
                            <span className="text-white">{user.name}</span>
                            <a href="/logout" className="text-white">Logout</a>
                        </>
                    ) : (
                        <>
                            <a href="/auth/login" className="text-white">Login</a>
                            <a href="/auth/register" className="text-white">Register</a>
                        </>
                    )}
                </div>
            </div>
        </nav>
    )
}

export default Navbar