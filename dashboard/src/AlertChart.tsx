import {BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer} from 'recharts'
import type {AlertCount} from './types'

interface Props{
    data: AlertCount[]
}

export default function AlertChart({data}:Props) {
    if (data.length === 0) return null

    return(
        <div className= "chart">
            <h2>Alerts by type</h2>
            <ResponsiveContainer width="100%" height={260}>
                <BarChart data={data}>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} />
                    <XAxis dataKey="kind"/>
                    <YAxis allowDecimals={false}/>
                    <Tooltip/>
                    <Bar dataKey="count" fill="#4a86e8" radius={[4,4,0,0]} />
                </BarChart>
            </ResponsiveContainer>
        </div>
    )
}